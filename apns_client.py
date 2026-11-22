"""
APNSClient — Python implementation of Apple Push Notification Service binary protocol.
Matches rustpush aps.rs field layout exactly.
"""
import os
import ssl
import socket
import struct
import time
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend


APNS_HOST = "courier.push.apple.com"
APNS_PORT = 5223


def _encode_tlv(field_id, value):
    return struct.pack('>B H', field_id, len(value)) + value


def _decode_tlvs(data):
    fields = {}
    i = 0
    while i < len(data):
        if i + 3 > len(data):
            break
        field_id, length = struct.unpack('>B H', data[i:i+3])
        i += 3
        fields[field_id] = data[i:i+length]
        i += length
    return fields


def _encode_message(command, payload):
    return struct.pack('>B I', command, len(payload)) + payload


def _generate_nonce():
    """[0x00] + [timestamp_ms: u64 BE] + [8 random bytes] = 17 bytes"""
    ts_ms = int(time.time()) * 1000
    return b'\x00' + struct.pack('>Q', ts_ms) + os.urandom(8)


def _sign_nonce(private_key_pem_bytes, nonce):
    """RSA PKCS1v15 + SHA1, prepend [0x01, 0x01]"""
    key = serialization.load_pem_private_key(private_key_pem_bytes, password=None)
    sig = key.sign(nonce, asym_padding.PKCS1v15(), hashes.SHA1())
    return bytes([1, 1]) + sig


class APNSClient:
    """
    Connects to Apple's push notification courier, authenticates with
    a device certificate, and obtains a 32-byte push token.
    """

    def __init__(self, cert_pem_path, key_pem_path, proxy_params=None):
        self.cert_pem_path = cert_pem_path
        self.key_pem_path = key_pem_path
        self.proxy_params = proxy_params
        self._token = None      # bytes, 32 bytes
        self._ssock = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self):
        """
        Conexión simplificada sin campos de autenticación (0x0C, 0x0D, 0x0E).
        Usado cuando Apple rechaza el handshake extendido.
        """
        # TLS Setup (Necesario para el socket)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers('DEFAULT@SECLEVEL=0')
        ctx.set_alpn_protocols(['apns-security-v2'])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Aunque eliminamos la autenticación de campos, 
        # mantenemos el load_cert_chain porque el handshake TLS lo exige
        ctx.load_cert_chain(certfile=self.cert_pem_path, keyfile=self.key_pem_path)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # --- Configuración de Proxy ---
        if self.proxy_params:
            sock.connect((self.proxy_params.get("host"), self.proxy_params.get("port")))
            req = f"CONNECT {APNS_HOST}:{APNS_PORT} HTTP/1.1\r\nHost: {APNS_HOST}:{APNS_PORT}\r\n"
            if self.proxy_params.get("auth"):
                auth_b64 = base64.b64encode(self.proxy_params.get("auth").encode()).decode()
                req += f"Proxy-Authorization: Basic {auth_b64}\r\n"
            req += "\r\n"
            sock.sendall(req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                resp += sock.recv(4096)
        else:
            sock.connect((APNS_HOST, APNS_PORT))

        self._ssock = ctx.wrap_socket(sock, server_hostname=APNS_HOST)

        # --- Payload Connect Simplificado (Solo campos básicos) ---
        payload = b''
        payload += _encode_tlv(0x02, struct.pack('>B', 1))          # State = 1
        payload += _encode_tlv(0x05, struct.pack('>I', 0b01000001)) # Flags
        payload += _encode_tlv(0x10, struct.pack('>H', 9))          # Version = 9

        self._ssock.sendall(_encode_message(0x07, payload))
        
        # --- Leer Respuesta (0x08) ---
        header = self._ssock.recv(5)
        if not header:
            raise ConnectionError("APNS cerró la conexión inesperadamente.")
            
        cmd, length = struct.unpack('>B I', header)
        body = self._ssock.recv(length)

        if cmd != 0x08:
            raise ConnectionError(f"Handshake fallido, se esperaba 0x08 pero llegó 0x{cmd:02x}")

        tlvs = _decode_tlvs(body)
        status = struct.unpack('>B', tlvs.get(1, b'\xff'))[0]
        if status != 0x00:
            raise ConnectionError(f"APNS rechazó la conexión (Estatus 0x{status:02x})")

        self._token = tlvs.get(3)
        if not self._token:
            raise ConnectionError("No se recibió el Push Token de 32 bytes.")

        # --- Mantener la sesión viva ---
        ss_payload = _encode_tlv(0x01, struct.pack('>B', 1))          # Status = 1
        ss_payload += _encode_tlv(0x02, struct.pack('>I', 0x7FFFFFFF)) # KeepAlive
        self._ssock.sendall(_encode_message(0x14, ss_payload))

        # --- Filtrado ---
        filter_payload = b''
        filter_payload += _encode_tlv(1, self._token)
        for topic in [b"com.apple.madrid", b"com.apple.ess", b"com.apple.cert", b"com.apple.ac"]:
            filter_payload += _encode_tlv(2, hashlib.sha1(topic).digest())
            
        self._ssock.sendall(_encode_message(0x09, filter_payload))
        return self._token

    def get_push_token(self) -> str:
        """Return push token as base64 string."""
        if not self._token:
            raise RuntimeError("Not connected — call connect() first")
        return base64.b64encode(self._token).decode('ascii')

    def get_push_token_hex(self) -> str:
        """Return push token as hex string."""
        if not self._token:
            raise RuntimeError("Not connected — call connect() first")
        return self._token.hex()

    def get_push_token_bytes(self) -> bytes:
        """Return raw 32-byte push token."""
        if not self._token:
            raise RuntimeError("Not connected — call connect() first")
        return self._token

    def send_message(self, topic: str, payload: bytes, msg_id: int = None) -> int:
        """
        Send an outbound message via APNs courier (command 0x0A).
        """
        import hashlib
        import random
        if not self._token:
            raise RuntimeError("Not connected — call connect() first")
        if msg_id is None:
            msg_id = random.randint(1, 0xFFFFFFFF)
            
        topic_hash = hashlib.sha1(topic.encode('utf-8')).digest()
        
        frame = b''
        frame += _encode_tlv(1, topic_hash)
        frame += _encode_tlv(2, self._token)
        frame += _encode_tlv(3, payload)
        frame += _encode_tlv(4, struct.pack('>I', msg_id))
        
        self._ssock.sendall(_encode_message(0x0A, frame))
        
        return msg_id

    def wait_for_message(self, timeout: float = 10.0) -> bytes:
        """
        Wait for an incoming message (command 0x0A) from APNs.
        Returns the parsed binary payload (TLV 3) or None if timeout.
        """
        if not self._ssock:
            raise RuntimeError("Not connected")
            
        self._ssock.settimeout(timeout)
        try:
            while True:
                header = self._ssock.recv(5)
                if not header:
                    return None
                if len(header) < 5:
                    continue
                
                cmd, length = struct.unpack('>B I', header)
                body = b''
                while len(body) < length:
                    chunk = self._ssock.recv(length - len(body))
                    if not chunk:
                        return None
                    body += chunk
                
                if cmd == 0x0A: # Incoming message
                    tlvs = _decode_tlvs(body)
                    # TLV 3 contains the actual payload
                    return tlvs.get(3)
                elif cmd == 0x08: # Error response
                    import binascii
                    print(f"[APNs] Error response received: {binascii.hexlify(body)}")
                    return None
                elif cmd in (0x0b, 0x0e, 0x0c, 0x0d): # ACK, Ping, Pong, KeepAlive variants
                    # Silently ignore APNs background chatter
                    continue
                else: # Unknown command
                    print(f"[APNs] Unknown command received: 0x{cmd:02x}")
        except socket.timeout:
            return None
        finally:
            self._ssock.settimeout(None)

    def close(self):
        if self._ssock:
            self._ssock.close()
            self._ssock = None


# ------------------------------------------------------------------
# Standalone test
# ------------------------------------------------------------------
if __name__ == '__main__':
    client = APNSClient('tmp/apns_certificate.pem', 'tmp/apns_private_key.pem')
    print("[*] Connecting to APNS...")
    client.connect()
    print(f"[+] push_token (hex): {client.get_push_token_hex()}")
    print(f"[+] push_token (b64): {client.get_push_token()}")
    client.close()
    print("[+] Done.")
