#!/usr/bin/env python3
"""
iMessage Sender - Script unificado
Carga session_cache.json, hace lookup de identidad, cifra y envía via APNS
"""
import os
import json
import ssl
import socket
import struct
import time
import base64
import hashlib
import binascii
import random
import subprocess
import plistlib
import gzip
import hmac
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

APNS_PORT = 5223


@dataclass
class DestinationDevice:
    push_token: bytes
    session_token: bytes
    public_identity_key: bytes


class Session:
    """Carga y maneja la sesión desde session_cache.json"""
    
    def __init__(self, cache_path: str = "session_cache.json"):
        with open(cache_path, 'r') as f:
            data = json.load(f)
        
        self.push_token = base64.b64decode(data["push_token"])
        self.auth_token = data["auth_token"]
        self.profile_id = data["profile_id"]
        self.handles = data["handles"]
        self.id_cert = base64.b64decode(data["id_cert"])
        self.auth_cert_der = base64.b64decode(data["auth_cert_der"])
        self.auth_key_pem = data["auth_key_pem"]
        self.push_cert_der = base64.b64decode(data["push_cert_der"])
        self.push_key_pem = data["push_key_pem"]
        self.identity_signing_key_pem = data["identity_signing_key_pem"]
        self.identity_encryption_key_pem = data["identity_encryption_key_pem"]
        self.hardware = data["hardware"]
        
        self.email = self.handles[0].replace("mailto:", "") if self.handles else ""
        self._save_pems()
    
    def _save_pems(self):
        """Guarda los PEMs a archivos para uso con APNS"""
        os.makedirs("tmp", exist_ok=True)
        
        with open("tmp/push_cert.pem", "w") as f:
            pem = "-----BEGIN CERTIFICATE-----\n"
            b64 = base64.b64encode(self.push_cert_der).decode()
            for i in range(0, len(b64), 64):
                pem += b64[i:i+64] + "\n"
            pem += "-----END CERTIFICATE-----\n"
            f.write(pem)
        
        with open("tmp/push_key.pem", "w") as f:
            f.write(self.push_key_pem)
        
        with open("tmp/auth_key.pem", "w") as f:
            f.write(self.auth_key_pem)
        
        with open("tmp/identity_signing.pem", "w") as f:
            f.write(self.identity_signing_key_pem)
        
        with open("tmp/identity_encryption.pem", "w") as f:
            f.write(self.identity_encryption_key_pem)
        
        with open("tmp/id_cert.pem", "w") as f:
            pem = "-----BEGIN CERTIFICATE-----\n"
            b64 = base64.b64encode(self.id_cert).decode()
            for i in range(0, len(b64), 64):
                pem += b64[i:i+64] + "\n"
            pem += "-----END CERTIFICATE-----\n"
            f.write(pem)
        
        print(f"[Session] Cargada: {self.email}")
        print(f"[Session] Profile ID: {self.profile_id}")
        print(f"[Session] Push token cargado: {len(self.push_token)} bytes (oculto)")


def normalize_handle(destination: str) -> str:
    """Normaliza una dirección IDS sin duplicar tel:/mailto:."""
    destination = destination.strip()
    if not destination:
        raise ValueError("El destinatario está vacío")
    if destination.startswith(('tel:', 'mailto:')):
        return destination
    return f"mailto:{destination}" if '@' in destination else f"tel:{destination}"


class IdentityLookup:
    """Hace lookup de identidad del destinatario usando query.py"""
    
    def __init__(self, session: Session, query_script: str = "query.py"):
        self.session = session
        self.query_script = query_script
    
    def lookup(self, destination: str) -> List[DestinationDevice]:
        """Consulta la identidad del destinatario"""
        if "@" in destination:
            uri = f"mailto:{destination}" if not destination.startswith("mailto:") else destination
        else:
            uri = f"tel:{destination}" if not destination.startswith("tel:") else destination
        
        print(f"[Lookup] Consultando: {uri}")
        
        cmd = [
            "python3", self.query_script,
            "--self-uri", f"mailto:{self.session.email}",
            "--key-priv", "tmp/auth_key.pem",
            "--key-cert", "tmp/id_cert.pem",
            "--push-key-priv", "tmp/push_key.pem",
            "--push-key-cert", "tmp/push_cert.pem",
            "--push-token-b64", base64.b64encode(self.session.push_token).decode(),
            uri
        ]
        
        try:
            if os.path.exists("identity.plist"):
                os.remove("identity.plist")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"[Lookup] query.py falló: {result.stderr[:400]}")
                return []
            print(f"[Lookup] stdout: {result.stdout[:300]}...")
            if os.path.exists("identity.plist"):
                return self._parse_identity_plist("identity.plist")
            print("[Lookup] No se generó identity.plist")
            return []
                
        except Exception as e:
            print(f"[Lookup] Error: {e}")
            return []
    
    def _parse_identity_plist(self, path: str) -> List[DestinationDevice]:
        """Parsea identity.plist y extrae dispositivos"""
        devices = []
        
        with open(path, 'rb') as f:
            content = f.read()
        
        xml_start = content.find(b"<?xml")
        if xml_start == -1:
            print("[Lookup] No se encontró XML en identity.plist")
            return []
        
        xml_content = content[xml_start:]
        
        try:
            data = plistlib.loads(xml_content)
        except Exception as e:
            print(f"[Lookup] Error parseando plist: {e}")
            return []
        
        self._extract_devices(data, devices)
        print(f"[Lookup] Encontrados {len(devices)} dispositivos")
        return devices
    
    def _extract_devices(self, obj, devices: List[DestinationDevice]):
        """Extrae dispositivos recursivamente del plist"""
        if isinstance(obj, dict):
            push_token = obj.get("push-token")
            session_token = obj.get("session-token")
            
            pub_key = obj.get("public-message-identity-key")
            if not pub_key and "client-data" in obj:
                client_data = obj["client-data"]
                if isinstance(client_data, dict):
                    pub_key = client_data.get("public-message-identity-key")
            
            if push_token and session_token and pub_key:
                if isinstance(push_token, str):
                    push_token = base64.b64decode(push_token)
                if isinstance(session_token, str):
                    session_token = base64.b64decode(session_token)
                if isinstance(pub_key, str):
                    pub_key = base64.b64decode(pub_key)
                
                print(f"[Lookup] Device found:")
                print(f"  Push token: {len(push_token)} bytes")
                print(f"  Session token: {len(session_token)} bytes")
                print(f"  Public key: {len(pub_key)} bytes")
                print(f"  Key hex: {pub_key[:48].hex()}")
                
                devices.append(DestinationDevice(
                    push_token=push_token,
                    session_token=session_token,
                    public_identity_key=pub_key
                ))
            
            for v in obj.values():
                self._extract_devices(v, devices)
        
        elif isinstance(obj, list):
            for item in obj:
                self._extract_devices(item, devices)


class IDSIdentityPublic:
    """Parser de public-message-identity-key (DER, etiquetas [1] y [2])."""

    @staticmethod
    def _read_tlv(data: bytes, offset: int):
        if offset >= len(data):
            raise ValueError("DER truncado: falta la etiqueta")
        tag = data[offset]
        offset += 1
        if offset >= len(data):
            raise ValueError("DER truncado: falta la longitud")
        first = data[offset]
        offset += 1
        if first & 0x80:
            nbytes = first & 0x7f
            if nbytes == 0 or nbytes > 4 or offset + nbytes > len(data):
                raise ValueError("Longitud DER inválida")
            size = int.from_bytes(data[offset:offset + nbytes], 'big')
            offset += nbytes
        else:
            size = first
        end = offset + size
        if end > len(data):
            raise ValueError("DER truncado: longitud excede el buffer")
        return tag, data[offset:end], end

    @staticmethod
    def parse(encoded: bytes):
        tag, sequence, end = IDSIdentityPublic._read_tlv(encoded, 0)
        if tag != 0x30 or end != len(encoded):
            raise ValueError("Identidad IDS: se esperaba SEQUENCE DER")
        offset = 0
        items = {}
        while offset < len(sequence):
            key_tag, value, offset = IDSIdentityPublic._read_tlv(sequence, offset)
            if key_tag not in (0x81, 0x82) or key_tag in items:
                raise ValueError(f"Etiqueta IDS desconocida o duplicada: {key_tag:#x}")
            items[key_tag] = value
        if 0x81 not in items or 0x82 not in items:
            raise ValueError("Identidad IDS sin una de las dos llaves")

        signing_raw, encryption_raw = items[0x81], items[0x82]
        for name, blob in (("EC", signing_raw), ("RSA", encryption_raw)):
            if len(blob) < 3 or int.from_bytes(blob[:2], 'big') != len(blob) - 2:
                raise ValueError(f"Longitud {name} inválida dentro de identidad IDS")

        ec_point = signing_raw[2:]
        verify_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ec_point)
        rsa_key = serialization.load_der_public_key(encryption_raw[2:])
        if not isinstance(rsa_key, rsa.RSAPublicKey):
            raise ValueError("La llave de cifrado IDS no es RSA")
        identity_hash = hashlib.sha256(signing_raw + encryption_raw).digest()
        return verify_key, rsa_key, identity_hash

    @staticmethod
    def _encode_length(n: int) -> bytes:
        if n < 128:
            return bytes([n])
        raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(raw)]) + raw

    @classmethod
    def from_public_keys(cls, signing_pub, encryption_pub) -> bytes:
        """Codifica la identidad como la publicada durante el registro IDS."""
        ec_data = signing_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint)
        rsa_data = encryption_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1)
        ec_blob = len(ec_data).to_bytes(2, 'big') + ec_data
        rsa_blob = len(rsa_data).to_bytes(2, 'big') + rsa_data
        sequence = (b'\x81' + cls._encode_length(len(ec_blob)) + ec_blob
                    + b'\x82' + cls._encode_length(len(rsa_blob)) + rsa_blob)
        return b'\x30' + cls._encode_length(len(sequence)) + sequence


class MessageCrypto:
    """Cifrado clásico iMessage E='pair'; NO es pair-ec/NGM."""
    NONCE = b'\x00' * 15 + b'\x01'

    def __init__(self, signing_private_pem: str, encryption_private_pem: str):
        self.signing_private = serialization.load_pem_private_key(
            signing_private_pem.encode() if isinstance(signing_private_pem, str) else signing_private_pem,
            password=None)
        self.encryption_private = serialization.load_pem_private_key(
            encryption_private_pem.encode() if isinstance(encryption_private_pem, str) else encryption_private_pem,
            password=None)
        if not isinstance(self.signing_private, ec.EllipticCurvePrivateKey):
            raise TypeError("identity_signing_key_pem debe contener una llave EC")
        if not isinstance(self.encryption_private, rsa.RSAPrivateKey):
            raise TypeError("identity_encryption_key_pem debe contener una llave RSA")
        self.sender_public_identity = IDSIdentityPublic.from_public_keys(
            self.signing_private.public_key(), self.encryption_private.public_key())
        _, _, self.sender_hash = IDSIdentityPublic.parse(self.sender_public_identity)

    def _der_to_raw(self, der_sig: bytes) -> bytes:
        """Convierte firma ECDSA DER a raw r||s (64 bytes para P-256)."""
        # DER: 30 [len] 02 [r_len] [r] 02 [s_len] [s]
        if der_sig[0] != 0x30:
            return der_sig
        
        offset = 2
        # Leer r
        r_len = der_sig[offset + 1]
        r = der_sig[offset + 2:offset + 2 + r_len]
        offset += 2 + r_len
        # Leer s
        s_len = der_sig[offset + 1]
        s = der_sig[offset + 2:offset + 2 + s_len]
        
        # Pad a 32 bytes cada uno
        r = r.lstrip(b'\x00').rjust(32, b'\x00')
        s = s.lstrip(b'\x00').rjust(32, b'\x00')
        
        return r + s

    def encrypt_sign_payload(self, recipient_public_identity: bytes, plaintext: bytes) -> bytes:
        _, recipient_rsa, recipient_hash = IDSIdentityPublic.parse(recipient_public_identity)
        random_seed = os.urandom(11)
        mac = hmac.new(
            random_seed,
            plaintext + b'\x02' + self.sender_hash + recipient_hash,
            hashlib.sha256).digest()
        aes_key = random_seed + mac[:5]

        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(self.NONCE))
        enc = cipher.encryptor()
        encrypted = enc.update(plaintext) + enc.finalize()

        rsa_part = recipient_rsa.encrypt(
            aes_key + encrypted[:100],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(), label=None))
        body = rsa_part + encrypted[100:]
        
        # Firma DER directamente (sin convertir a raw)
        signature = self.signing_private.sign(body, ec.ECDSA(hashes.SHA1()))
        
        packet = (b'\x02' + len(body).to_bytes(2, 'big') + body
                + bytes([len(signature)]) + signature)
        return packet

    def decrypt_payload(self, encrypted: bytes) -> Optional[bytes]:
        """Descifra un payload pair recibido."""
        try:
            if encrypted[0] != 0x02:
                print("[Crypto] Formato no es pair (0x02)")
                return None
            
            body_len = int.from_bytes(encrypted[1:3], 'big')
            body = encrypted[3:3+body_len]
            sig_len = encrypted[3+body_len]
            sig = encrypted[4+body_len:4+body_len+sig_len]
            
            # RSA decrypt (nuestra private key)
            rsa_len = (self.encryption_private.key_size + 7) // 8
            if len(body) < rsa_len:
                print("[Crypto] Body demasiado corto")
                return None
            
            rsa_part = body[:rsa_len]
            encrypted_rest = body[rsa_len:]
            
            unpacked = self.encryption_private.decrypt(
                rsa_part,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                             algorithm=hashes.SHA1(), label=None))
            
            aes_key = unpacked[:16]
            enc_start = unpacked[16:]
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(self.NONCE))
            dec = cipher.decryptor()
            plaintext = dec.update(enc_start + encrypted_rest) + dec.finalize()
            
            print(f"[Crypto] Descifrado OK: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            print(f"[Crypto] Error descifrando: {e}")
            return None


def run_pair_self_test():
    """Verifica parser, cifrado y firma sin utilizar credenciales reales."""
    sender_ec = ec.generate_private_key(ec.SECP256R1())
    sender_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1280)
    recipient_ec = ec.generate_private_key(ec.SECP256R1())
    recipient_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1280)
    def pem(key):
        return key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
    crypto = MessageCrypto(pem(sender_ec), pem(sender_rsa))
    recipient_id = IDSIdentityPublic.from_public_keys(
        recipient_ec.public_key(), recipient_rsa.public_key())
    assert len(recipient_id) == 249, "Codificación de identidad inesperada"
    sig_pub, rsa_pub, _ = IDSIdentityPublic.parse(recipient_id)
    assert rsa_pub.key_size == 1280
    assert sig_pub.public_numbers() == recipient_ec.public_key().public_numbers()
    for raw in (b'hola', b'un mensaje de prueba ' * 30):
        encrypted = crypto.encrypt_sign_payload(recipient_id, raw)
        assert encrypted[0] == 2
        body_len = int.from_bytes(encrypted[1:3], 'big')
        body = encrypted[3:3+body_len]
        sig_len = encrypted[3+body_len]
        sig = encrypted[4+body_len:]
        assert len(sig) == sig_len
        sender_ec.public_key().verify(sig, body, ec.ECDSA(hashes.SHA1()))
        rsa_len = (recipient_rsa.key_size + 7) // 8
        unpacked = recipient_rsa.decrypt(
            body[:rsa_len],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None))
        key, enc_start = unpacked[:16], unpacked[16:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(MessageCrypto.NONCE))
        dec = cipher.decryptor()
        plaintext = dec.update(enc_start + body[rsa_len:]) + dec.finalize()
        assert plaintext == raw
    print('[SELF-TEST] OK: parser IDS, derivación, AES-CTR, RSA-OAEP y ECDSA')


class MessageBuilder:
    """Construye el binary plist del mensaje"""
    
    def __init__(self, session: Session):
        self.session = session
        self.crypto = MessageCrypto(session.identity_signing_key_pem, session.identity_encryption_key_pem)
        self.last_uuid = None
    
    def build(self, text: str, destination: str, devices: List[DestinationDevice]) -> Tuple[bytes, bytes]:
        """
        Construye el binary plist del mensaje
        Retorna (binary_plist, message_id)
        """
        msg_uuid = uuid.uuid4().bytes
        self.last_uuid = msg_uuid
        message_id = os.urandom(4)
        madrid_id = struct.unpack('>I', message_id)[0]
        
        sender = f"mailto:{self.session.email}"
        
        inner_payload = self._build_inner_payload(text, sender, destination, msg_uuid)
        print(f"[Builder] Inner payload: {len(inner_payload)} bytes")
        
        dtl = []
        for i, device in enumerate(devices):
            print(f"[Builder] Encrypting for device {i+1}...")
            if device.push_token == self.session.push_token:
                print("[Builder] Ignorando dispositivo propio")
                continue
            encrypted = self.crypto.encrypt_sign_payload(
                device.public_identity_key, inner_payload)
            
            if encrypted:
                dtl.append({
                    "P": encrypted,
                    "D": True,
                    "sT": device.session_token,
                    "t": device.push_token,
                    "tP": destination
                })
                print(f"[Builder] Device {i+1} encrypted OK")
            else:
                print(f"[Builder] Device {i+1} encryption failed")
        
        if not dtl:
            raise Exception("No se pudo cifrar para ningún dispositivo")
        
        madrid_dict = {
            "c": 100,
            "fcn": 1,
            "E": "pair",
            "ua": "[iPhone OS,18.7.10,22H374,iPad7,11]",
            "v": 8,
            "i": madrid_id,
            "U": msg_uuid,
            "sP": sender,
            "dtl": dtl
        }
        
        binary_plist = plistlib.dumps(madrid_dict, fmt=plistlib.FMT_BINARY)
        print(f"[Builder] Final plist: {len(binary_plist)} bytes")
        
        return binary_plist, message_id
    
    def _build_inner_payload(self, text: str, sender: str, destination: str, uuid_bytes: bytes) -> bytes:
        """Plist de texto Madrid: luego gzip y cifrado pair."""
        inner = {
            "gid": str(uuid.UUID(bytes=uuid_bytes)).upper(),
            "gv": "8",
            "p": [sender, destination],
            "pv": 0,
            "r": str(uuid.UUID(bytes=uuid_bytes)).upper(),
            "t": text,
            "v": "1",
        }
        raw = plistlib.dumps(inner, fmt=plistlib.FMT_BINARY)
        return gzip.compress(raw, mtime=0)


class APNSClient:
    """Cliente APNS Courier"""
    
    def __init__(self, cert_path: str, key_path: str, session: Session = None):
        self.cert_path = cert_path
        self.key_path = key_path
        self.session = session
        self.crypto = None
        if session:
            self.crypto = MessageCrypto(session.identity_signing_key_pem, session.identity_encryption_key_pem)
        self._token = None
        self._ssock = None
        self._pending_notifications = []
        self._rxbuffer = bytearray()

    def connect(self, token: bytes):
        """Conecta a APNS con el token dado"""
        host = f"{random.randint(1, 50)}-courier.push.apple.com"
        print(f"[APNS] Conectando a {host}:{APNS_PORT}...")
        
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers('DEFAULT@SECLEVEL=0')
        ctx.set_alpn_protocols(['apns-security-v2'])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        
        sock = socket.create_connection((host, APNS_PORT), timeout=15)
        self._ssock = ctx.wrap_socket(sock, server_hostname="courier.push.apple.com")
        
        print(f"[APNS] TLS: {self._ssock.version()}")
        
        flags = 0x45
        print(f"[APNS] CONNECT flags: 0x{flags:02X}")

        payload = b""
        payload += self._encode_tlv(0x01, token)
        payload += self._encode_tlv(0x02, b"\x01")
        payload += self._encode_tlv(0x05, struct.pack(">I", flags))

        self._ssock.sendall(self._encode_message(0x07, payload))

        cmd, body = self._recv_frame(timeout=15.0)
        if cmd != 0x08:
            raise RuntimeError(f"Se esperaba CONN_ACK, llegó 0x{cmd:02X}")
        
        tlvs = self._decode_tlvs(body)
        status = tlvs.get(1)
        if status != b'\x00':
            raise RuntimeError(f"CONNECT falló")
        
        self._token = token
        server_token = tlvs.get(3)

        print("[APNS] CONNECT status:", status.hex() if status else "ausente")
        print("[APNS] Token inicial:", len(token), "bytes")
        print("[APNS] Token servidor:", len(server_token) if server_token else "no proporcionado")

        if server_token and len(server_token) == 32:
            print("[APNS] Token cambiado:", server_token != token)
                
        ss_payload = (
            self._encode_tlv(0x01, struct.pack('>B', 1)) +
            self._encode_tlv(0x02, struct.pack('>I', 0x7FFFFFFF))
        )
        self._ssock.sendall(self._encode_message(0x14, ss_payload))
        time.sleep(0.3)
        
        self._drain_control_frames("SET_STATE", timeout=0.5)

        topic_hash = hashlib.sha1(b"com.apple.madrid").digest()
        filter_payload = (self._encode_tlv(1, self._token) + self._encode_tlv(2, topic_hash))
        print("[APNS] Enviando FILTER...")
        self._ssock.sendall(self._encode_message(0x09, filter_payload))
        self._drain_control_frames("FILTER", timeout=1.0)

        print("[APNS] Listo")
    
    def _drain_control_frames(self, context: str, timeout: float):
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                try:
                    cmd, body = self._recv_frame(deadline - time.monotonic())
                except socket.timeout:
                    break
                if cmd == 0x0A:
                    self._queue_inbound_notification(body)
                    print(f"[APNS] {context}: notificación encolada")
                elif cmd == 0x0E:
                    print(f"[APNS] {context}: NO_STORAGE")
                elif cmd == 0x08:
                    fields = self._decode_tlvs(body)
                    server_token = fields.get(3)
                    if server_token and len(server_token) == 32:
                        self._token = server_token
                    print(f"[APNS] {context}: CONN_ACK adicional")
                else:
                    print(f"[APNS] {context}: cmd=0x{cmd:02X} len={len(body)}")
        finally:
            self._ssock.settimeout(None)

    def listen(self, on_message, timeout: float = None):
        print("[APNS] Escuchando TODAS las notificaciones...")
        deadline = time.monotonic() + timeout if timeout else None
        
        try:
            while True:
                if deadline and time.monotonic() >= deadline:
                    break
                
                try:
                    remaining = (deadline - time.monotonic()) if deadline else 30.0
                    cmd, body = self._recv_frame(max(0.1, remaining))
                except socket.timeout:
                    continue
                except ConnectionError:
                    print("[APNS] Conexión cerrada")
                    break
                
                if cmd != 0x0A:
                    continue
                
                self._queue_inbound_notification(body)
                
                fields = self._decode_tlvs(body)
                msg_bytes = fields.get(3)
                if not msg_bytes:
                    continue
                
                try:
                    msg = plistlib.loads(msg_bytes)
                except Exception:
                    continue
                
                if not isinstance(msg, dict):
                    continue
                
                c = msg.get("c", "?")
                keys = list(msg.keys())
                has_P = "P" in msg
                has_dtl = "dtl" in msg and len(msg.get("dtl", [])) > 0
                
                print(f"[ALL] c={c} P={has_P} dtl={has_dtl} keys={keys}")
                
                if has_P or has_dtl:
                    print(f"[ALL] ¡¡¡ ENCONTRADO !!!")
                    print(f"[ALL] Full: {msg}")
                
                if msg.get("c") == 100:
                    self._handle_incoming_message(msg, on_message)
                    
        except KeyboardInterrupt:
            print("\n[APNS] Escucha detenida")
        
    def _handle_incoming_message(self, msg: dict, on_message):
        sender = msg.get("sP", "unknown")
        dtl = msg.get("dtl", [])
        msg_uuid = msg.get("U")
        
        print(f"[IDS] Mensaje de: {sender}")
        print(f"[IDS] Keys: {list(msg.keys())}")
        print(f"[IDS] dtl count: {len(dtl)}")
        
        # DEBUG: dump del mensaje completo (sin bytes largos)
        for k, v in msg.items():
            if isinstance(v, bytes):
                print(f"[IDS]   {k}: bytes({len(v)}) = {v[:32].hex()}...")
            elif isinstance(v, list):
                print(f"[IDS]   {k}: list({len(v)})")
            else:
                print(f"[IDS]   {k}: {v}")
        
        my_token = self._token
        found = False
        
        for i, entry in enumerate(dtl):
            entry_token = entry.get("t")
            token_hex = entry_token.hex()[:16] if entry_token else "None"
            print(f"[IDS] Device {i}: token={token_hex}...")
            
            if entry_token == my_token:
                encrypted = entry.get("P")
                if encrypted:
                    try:
                        plaintext = self._decrypt_payload(encrypted)
                        if plaintext:
                            text = self._extract_text(plaintext)
                            on_message(sender, text, msg)
                            found = True
                            
                            if msg_uuid:
                                self._send_delivery_receipt(sender, msg_uuid)
                            break
                    except Exception as e:
                        print(f"[Crypto] Error: {e}")
        
        if not found:
            print("[IDS] No se encontró payload para nuestro token")
            print(f"[IDS] Nuestro token: {my_token.hex()[:16]}...")
    
    def _extract_text(self, plaintext: bytes) -> str:
        """Extrae el texto del payload interno (gzip + binary plist)."""
        try:
            decompressed = gzip.decompress(plaintext)
            inner = plistlib.loads(decompressed)
            return inner.get("t", "")
        except Exception as e:
            print(f"[Extract] Error: {e}")
            return ""

    def _send_delivery_receipt(self, to_handle: str, msg_uuid: bytes):
        """Envía c=101 para que el remitente vea 'entregado'."""
        if not self.session:
            print("[IDS] No hay session para enviar recibo")
            return
        
        receipt = {
            "c": 101,
            "s": 0,
            "U": msg_uuid,
            "sP": f"mailto:{self.session.email}",
            "tP": to_handle,
        }
        
        binary = plistlib.dumps(receipt, fmt=plistlib.FMT_BINARY)
        msg_id = os.urandom(4)
        
        topic_hash = hashlib.sha1(b"com.apple.madrid").digest()
        frame = (
            self._encode_tlv(1, topic_hash) +
            self._encode_tlv(2, self._token) +
            self._encode_tlv(3, binary) +
            self._encode_tlv(4, msg_id)
        )
        
        self._ssock.sendall(self._encode_message(0x0A, frame))
        print(f"[IDS] Recibo de entrega (c=101) enviado")

    def _read_all_responses(self, context: str):
        self._drain_control_frames(context, timeout=0.5)

    def send_message(self, topic: str, payload: bytes, msg_id: bytes) -> int:
        """Publica un único payload Madrid; dtl contiene los destinos."""
        if self._token is None or len(self._token) != 32:
            raise ValueError("Token del emisor ausente o inválido")
        if len(msg_id) != 4:
            raise ValueError("msg_id debe tener 4 bytes")
        msg_id_int = int.from_bytes(msg_id, 'big')
        topic_hash = hashlib.sha1(topic.encode('utf-8')).digest()
        frame = (self._encode_tlv(1, topic_hash)
                 + self._encode_tlv(2, self._token)
                 + self._encode_tlv(3, payload)
                 + self._encode_tlv(4, msg_id))
        self._ssock.sendall(self._encode_message(0x0A, frame))
        print(f"[APNS] MESSAGE enviado: topic={topic}, id={msg_id_int}, bytes={len(payload)}")
        return msg_id_int

    def _recv_frame(self, timeout: float):
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if len(self._rxbuffer) >= 5:
                cmd, length = struct.unpack('>BI', self._rxbuffer[:5])
                if length > 1024 * 1024:
                    raise ValueError(f"Trama APNs excesiva: {length} bytes")
                total = 5 + length
                if len(self._rxbuffer) >= total:
                    body = bytes(self._rxbuffer[5:total])
                    del self._rxbuffer[:total]
                    return cmd, body
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("Trama APNs incompleta; bytes conservados")
            self._ssock.settimeout(remaining)
            chunk = self._ssock.recv(4096)
            if not chunk:
                raise ConnectionError("Socket APNs cerrado")
            self._rxbuffer.extend(chunk)

    def wait_ack(self, msg_id: bytes, timeout: float = 10.0) -> bool:
        until = time.monotonic() + timeout
        try:
            while time.monotonic() < until:
                try:
                    cmd, body = self._recv_frame(max(0.1, until - time.monotonic()))
                except socket.timeout:
                    break
                if cmd != 0x0B:
                    if cmd == 0x0A:
                        self._queue_inbound_notification(body)
                    print(f"[APNS] Trama anterior al ACK: 0x{cmd:02X}")
                    continue
                fields = self._decode_tlvs(body)
                ack_id = fields.get(4)
                if ack_id != msg_id:
                    print("[APNS] ACK de otro mensaje; ignorando")
                    continue
                status = fields.get(8, b'')
                if len(status) != 1:
                    print('[APNS] ACK sin status válido')
                    return False
                print(f'[APNS] ACK id={ack_id.hex()} status=0x{status[0]:02X}')
                return status == b'\x00'
        finally:
            self._ssock.settimeout(None)
        print('[APNS] No llegó ACK del mensaje')
        return False

    def _queue_inbound_notification(self, body: bytes):
        fields = self._decode_tlvs(body)
        inbound_id = fields.get(4)
        if inbound_id and len(inbound_id) == 4 and self._token:
            frame = (
                self._encode_tlv(1, self._token)
                + self._encode_tlv(4, inbound_id)
                + self._encode_tlv(8, b'\x00')
            )
            self._ssock.sendall(self._encode_message(0x0B, frame))
            print(f'[APNS] ACK de notificación entrante id={inbound_id.hex()}')
        self._pending_notifications.append(body)

    def wait_delivery(self, uuid_bytes: bytes, message_id: bytes,
                      expected_devices: int = 1, timeout: float = 20.0) -> bool:
        wanted_i = int.from_bytes(message_id, 'big')
        accepted = 0
        delivery_receipts = 0
        seen = set()
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if self._pending_notifications:
                    body = self._pending_notifications.pop(0)
                else:
                    try:
                        cmd, body = self._recv_frame(max(0.1, deadline - time.monotonic()))
                    except socket.timeout:
                        break
                    if cmd != 0x0A:
                        print(f'[APNS] Trama de espera cmd=0x{cmd:02X}')
                        continue
                    self._queue_inbound_notification(body)
                    body = self._pending_notifications.pop(0)

                fields = self._decode_tlvs(body)
                msg_bytes = fields.get(3)
                if not msg_bytes:
                    print('[IDS] Notificación sin payload TLV 3')
                    continue
                try:
                    msg = plistlib.loads(msg_bytes)
                except (ValueError, TypeError, plistlib.InvalidFileException):
                    print('[IDS] Notificación con contenido no plist')
                    continue
                if not isinstance(msg, dict):
                    continue

                command = msg.get('c')
                status = msg.get('s')
                matches_uuid = msg.get('U') == uuid_bytes
                matches_id = msg.get('i') == wanted_i

                if command == 255:
                    if matches_uuid or matches_id:
                        token = msg.get('t')
                        token_hint = token.hex()[:8] if isinstance(token, bytes) else 'sin-token'
                        key = ('255', fields.get(4), msg.get('i'), msg.get('U'))
                        if key not in seen:
                            seen.add(key)
                            accepted += 1
                        print(f'[IDS] c=255 para este envío: s={status}, '
                              f'correlación={"U" if matches_uuid else "i"}, '
                              f'dispositivo={token_hint}...')
                        if status not in (0, 5008):
                            print('[IDS] IDS reportó un estado de error o no esperado')
                    else:
                        print(f'[IDS] c=255 de otro mensaje; i={msg.get("i")}; s={status}')
                elif command == 101:
                    if matches_uuid:
                        if status == 0:
                            delivery_receipts += 1
                        print(f'[IDS] c=101 recibo de entrega: s={status}')
                    else:
                        print('[IDS] c=101 de otro UUID')
                else:
                    print(f'[IDS] Mensaje de control c={command}')
        finally:
            self._ssock.settimeout(None)

        print(f'[IDS] Resumen: respuestas c=255={accepted}, '
              f'recibos c=101={delivery_receipts}, '
              f'dispositivos dirigidos={expected_devices}')
        if accepted == 0:
            print('[IDS] No se observó una respuesta c=255 correlacionada')
        if delivery_receipts == 0:
            print('[IDS] No se observó recibo c=101: entrega al dispositivo sin confirmar')
        return delivery_receipts > 0

    def close(self):
        if self._ssock:
            try:
                self._ssock.close()
            except:
                pass
            self._ssock = None
    
    def _encode_tlv(self, field_id: int, value: bytes) -> bytes:
        return struct.pack('>BH', field_id, len(value)) + value
    
    def _decode_tlvs(self, data: bytes) -> dict:
        fields = {}
        i = 0
        while i + 3 <= len(data):
            field_id, length = struct.unpack('>BH', data[i:i + 3])
            i += 3
            if i + length > len(data):
                break
            fields[field_id] = data[i:i + length]
            i += length
        return fields
    
    def _encode_message(self, command: int, payload: bytes) -> bytes:
        return struct.pack('>BI', command, len(payload)) + payload
    
    def _recv_exact(self, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = self._ssock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket cerrado")
            buf += chunk
        return buf



def verify_keys(session: Session):
    """Verifica que la identidad generada coincida con las llaves cargadas."""
    signing_key = serialization.load_pem_private_key(
        session.identity_signing_key_pem.encode(), password=None)
    encryption_key = serialization.load_pem_private_key(
        session.identity_encryption_key_pem.encode(), password=None)
    
    generated = IDSIdentityPublic.from_public_keys(
        signing_key.public_key(),
        encryption_key.public_key()
    )
    
    print(f"\n[Verify] Identidad generada ({len(generated)} bytes):")
    print(f"  {base64.b64encode(generated).decode()}")
    print(f"  Hex: {generated[:20].hex()}...")
    # Comparar con la del registro (pega aquí el public-message-identity-key del plist)
    registered_b64 = "MIH2gUMAQQQ8u7ZQbuLFMlzbxIU3ZTKjjc7imQ0I3oxeS4x1pDo5wxV2YPtAuR0KE1tO/FOWAhqSxy+MdT4Ym29R33SdCOZogoGuAKwwgakCgaEAs7s1kR8Yj5vmaIX0HyjlunIxk90ug+wxjCG1IvKnYNEZsDr+t3sefjPV1nqsTkkgJETUjdGxfvnbsUSiQzzBOUp2XXSMdsEGrK8CShfDCFN7+xkkWr8KhYEyRuWrKnr7DaE6+TTiQtnpZygYnpM+oltyrV6P6WafOeMcWqokvT7X8NGEi6SnB0fZZC1O3E4sAZHekeha/QbfZsubWOBuBwIDAQAB"  # del plist de registro
    registered = base64.b64decode(registered_b64)
    if generated == registered:
        print("[Verify] ✓ Coincide con el registro")
    else:
        print("[Verify] ✗ NO coincide con el registro")
    return generated


class iMessageSender:
    """Clase principal para enviar iMessages"""
    
    def __init__(self, session_path: str = "session_cache.json", query_script: str = "query.py"):
        self.session = Session(session_path)
        self.lookup = IdentityLookup(self.session, query_script)
        self.builder = MessageBuilder(self.session)
        self.apns = None

    def send(self, destination: str, text: str) -> bool:
        """Envía un iMessage"""
        print(f"\n{'='*60}")
        print(f"[iMessage] Enviando a: {destination}")
        print(f"[iMessage] Texto: {text}")
        print(f"{'='*60}\n")
        
        verify_keys(self.session)
    
        devices = self.lookup.lookup(destination)
        if not devices:
            print("[iMessage] ❌ No se encontraron dispositivos")
            return False
        
        dest_uri = normalize_handle(destination)
        print(f"[iMessage] Handle normalizado: {dest_uri}")
        binary_plist, message_id = self.builder.build(text, dest_uri, devices)
        
        self.apns = APNSClient("tmp/push_cert.pem", "tmp/push_key.pem", self.session)
        self.apns.connect(self.session.push_token)
        
        try:
            self.apns.send_message('com.apple.madrid', binary_plist, message_id)
            if not self.apns.wait_ack(message_id, timeout=10):
                print('[iMessage] Rechazado por APNs o ACK ausente')
                return False
            print('[iMessage] ACK APNs 0x00. Esperando confirmación IDS c=255...')
            outer = plistlib.loads(binary_plist)
            delivered = self.apns.wait_delivery(
                self.builder.last_uuid, message_id,
                expected_devices=len(outer.get('dtl', [])), timeout=20)
            if not delivered:
                print('[iMessage] APNs aceptó el paquete, pero no se confirmó entrega IDS')
            return delivered
        finally:
            self.apns.close()




if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="iMessage Sender (pair clásico + diagnóstico IDS)")
    parser.add_argument("--session", default="session_cache.json")
    parser.add_argument("--query", default="query.py")
    parser.add_argument("--to", help="Destinatario (correo o teléfono)")
    parser.add_argument("--message", help="Texto del mensaje")
    parser.add_argument("--self-test", action="store_true", help="Prueba de cifrado local; sin red")
    parser.add_argument("--listen", action="store_true", help="Escuchar iMessages entrantes")
    parser.add_argument("--listen-timeout", type=float, default=None, help="Timeout de escucha en segundos")
    args = parser.parse_args()

    if args.self_test:
        run_pair_self_test()
    
    elif args.listen:
        session = Session(args.session)
        
        def on_imessage(sender, text, raw):
            print(f"\n{'='*50}")
            print(f"De: {sender}")
            print(f"Texto: {text}")
            print(f"{'='*50}\n")
        
        apns = APNSClient("tmp/push_cert.pem", "tmp/push_key.pem", session)
        apns.connect(session.push_token)
        
        try:
            apns.listen(on_imessage, timeout=args.listen_timeout)
        except KeyboardInterrupt:
            print("\n[iMessage] Escucha detenida")
        finally:
            apns.close()
    
    else:
        if not args.to or args.message is None:
            parser.error("Se requieren --to y --message, o bien --listen / --self-test")
        
        sender = iMessageSender(args.session, args.query)
        ok = sender.send(args.to, args.message)
        if ok:
            print("\n✅ Confirmación IDS recibida (verificar recepción en el iPhone)")
        else:
            print("\n⚠️ Entrega no confirmada; revisar status IDS")