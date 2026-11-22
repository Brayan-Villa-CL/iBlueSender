import os
import sys
import time
import struct
import base64
import gzip
import plistlib
import httpx
import argparse
import asyncio
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class AppleIdsProtocol:
    
    @staticmethod
    def _clean_pem_cert(pem_str: str) -> str:
        """Limpia el certificado PEM para dejar solo el Base64 en una línea."""
        if not pem_str:
            return ""
        lines = [line.strip() for line in pem_str.splitlines() if not line.startswith("-----")]
        return "".join(lines)

    @staticmethod
    def _compose_and_sign(private_key_pem: str, bag_key: str, qstr: str, body_gz_bytes: bytes, push_token_bytes: bytes) -> tuple:
        """Genera el Nonce y la Firma (Signature) en Base64."""
        ms_now = int(time.time() * 1000)
        ms_bytes = struct.pack('>Q', ms_now)
        rand8 = os.urandom(8)
        nonce = b'\x01' + ms_bytes + rand8

        payload = bytearray(nonce)
        
        def add_field(data_bytes):
            payload.extend(struct.pack('>I', len(data_bytes)))
            payload.extend(data_bytes)

        add_field(bag_key.encode('utf-8'))
        add_field(qstr.encode('utf-8'))
        add_field(body_gz_bytes)
        add_field(push_token_bytes)

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'), 
            password=None
        )
        
        raw_signature = private_key.sign(
            payload,
            padding.PKCS1v15(),
            hashes.SHA1()
        )

        wire_signature = b'\x01\x01' + raw_signature
        return base64.b64encode(nonce).decode('utf-8'), base64.b64encode(wire_signature).decode('utf-8')

    @classmethod
    async def execute_query_async(cls, url: str, self_uri: str, target_uris: list,
                                  id_priv_key_pem: str, id_cert_pem: str,
                                  push_priv_key_pem: str, push_cert_pem: str, push_token_b64: str,
                                  x_apple_imd: str = "", x_apple_imd_m: str = "", x_apple_imd_rinfo: str = "",
                                  baa_cert: str = "", baa_sign: str = "", baa_sig_alt: str = "", baa_time: str = ""):
        
        plist_dict = {"uris": target_uris}
        body_xml_bytes = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)
        body_gz_bytes = gzip.compress(body_xml_bytes, compresslevel=9)

        push_token_bytes = base64.b64decode(push_token_b64)
        
        qstr = ""
        id_nonce_b64, id_sig_b64 = cls._compose_and_sign(id_priv_key_pem, "id-query", qstr, body_gz_bytes, push_token_bytes)
        push_nonce_b64, push_sig_b64 = cls._compose_and_sign(push_priv_key_pem, "id-query", qstr, body_gz_bytes, push_token_bytes)

        clean_id_cert = cls._clean_pem_cert(id_cert_pem)
        clean_push_cert = cls._clean_pem_cert(push_cert_pem)
        
        client_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        headers = {
            "Content-Type": "application/x-apple-plist",
            "Content-Encoding": "gzip",
            "Accept": "*/*",
            "Accept-Language": "es-xl",
            "Accept-Encoding": "gzip",
            "User-Agent": "com.apple.madrid-lookup [macOS,11.7.10,20G1427,MacBookPro9,1]",
            "Connection": "keep-alive",
            "x-id-self-uri": self_uri,
            "x-protocol-version": "1650",
            "x-apple-i-locale": "en_US",
            "x-apple-i-timezone": "GMT+0",
            "X-Apple-I-Client-Time": client_time,
            "x-id-sig": id_sig_b64,
            "x-id-nonce": id_nonce_b64,
            "x-id-cert": clean_id_cert,
            "x-push-sig": push_sig_b64,
            "x-push-nonce": push_nonce_b64,
            "x-push-cert": clean_push_cert,
            "x-push-token": push_token_b64,
            "x-apple-baa-supported": "1",
            "x-apple-baa-version": "1",
            "x-apple-header-source": "0"
        }

        if x_apple_imd: headers["X-Apple-I-MD"] = x_apple_imd
        if x_apple_imd_m: headers["X-Apple-I-MD-M"] = x_apple_imd_m
        if x_apple_imd_rinfo: headers["X-Apple-I-MD-RINFO"] = x_apple_imd_rinfo
        if baa_cert: headers["x-apple-baa-cert"] = baa_cert
        if baa_sign: headers["x-apple-baa-sig"] = baa_sign
        if baa_sig_alt: headers["x-apple-baa-sig-alt"] = baa_sig_alt
        if baa_time: headers["x-apple-baa-time"] = baa_time

        # 5. Petición HTTP/2
        async with httpx.AsyncClient(http2=True, verify=False) as client:
            response = await client.post(url, content=body_gz_bytes, headers=headers)
            
            if response.status_code != 200:
                raise Exception(f"HTTP Error {response.status_code}: {response.text}")
            
            try:
                # 1. Cargar el plist (viene en binario desde Apple)
                parsed_plist = plistlib.loads(response.content)
                
                # 2. Convertir ese diccionario a bytes en formato XML estricto
                xml_bytes = plistlib.dumps(parsed_plist, fmt=plistlib.FMT_XML)
                
                # 3. Decodificar los bytes a un string de texto normal
                return xml_bytes.decode('utf-8')
                
            except plistlib.InvalidFileException:
                # Si Apple devuelve un error que no es plist, mostramos el texto crudo
                return response.text

# =====================================================================
# INTEGRACIÓN CLI (Manejo de Argumentos)
# =====================================================================
async def main():
    # Forzar la salida de consola en Windows a UTF-8 para evitar errores de charmap
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding='utf-8')

    parser = argparse.ArgumentParser(description="Query IDS 'id-query' por HTTP/2 con firmas ID y PUSH.")
    
    # Argumentos requeridos y opcionales
    parser.add_argument("--url", default="https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query", help="URL del servicio IDS")
    parser.add_argument("--self-uri", required=True, help="URI de identidad propia (ej. mailto:tu@email.com)")
    parser.add_argument("--key-priv", required=True, help="Ruta a la llave privada ID (ej. ids_priv.pem)")
    parser.add_argument("--key-cert", required=True, help="Ruta al certificado ID (ej. com.apple.madrid_X.pem)")
    
    # Si no se pasan los de PUSH, el script usará los de ID como fallback
    parser.add_argument("--push-key-priv", help="Ruta a la llave privada PUSH (Opcional)")
    parser.add_argument("--push-key-cert", help="Ruta al certificado PUSH (Opcional)")
    
    parser.add_argument("--push-token-b64", required=True, help="Push Token en Base64")
    
    # Argumentos adicionales BAA y Anisette (Opcionales)
    parser.add_argument("--imd", default="", help="Header X-Apple-I-MD")
    parser.add_argument("--imd-m", default="", help="Header X-Apple-I-MD-M")
    parser.add_argument("--imd-rinfo", default="", help="Header X-Apple-I-MD-RINFO")
    parser.add_argument("--baa-cert", default="", help="Certificado BAA en Base64")
    
    # 'uris' captura todos los argumentos que queden al final (tel:..., mailto:...)
    parser.add_argument("uris", nargs="+", help="URIs objetivo a consultar (ej. tel:+524772860920)")

    args = parser.parse_args()

    # Lógica de fallback: Si no hay llaves PUSH, reutiliza las de ID (igual que tu script Bash)
    push_priv_path = args.push_key_priv if args.push_key_priv else args.key_priv
    push_cert_path = args.push_key_cert if args.push_key_cert else args.key_cert

    try:
        # Leer el contenido de los archivos pasados por argumento
        with open(args.key_priv, "r", encoding="utf-8") as f: id_priv_pem = f.read()
        with open(args.key_cert, "r", encoding="utf-8") as f: id_cert_pem = f.read()
        with open(push_priv_path, "r", encoding="utf-8") as f: push_priv_pem = f.read()
        with open(push_cert_path, "r", encoding="utf-8") as f: push_cert_pem = f.read()
    except FileNotFoundError as e:
        print(f"❌ Error al leer el archivo: {e}")
        return

    print(f"→ POST (HTTP/2) {args.url}")
    print(f"Buscando identidades para: {', '.join(args.uris)}")

    try:
        resultado = await AppleIdsProtocol.execute_query_async(
            url=args.url,
            self_uri=args.self_uri,
            target_uris=args.uris,
            id_priv_key_pem=id_priv_pem,
            id_cert_pem=id_cert_pem,
            push_priv_key_pem=push_priv_pem,
            push_cert_pem=push_cert_pem,
            push_token_b64=args.push_token_b64,
            
            x_apple_imd=args.imd,
            x_apple_imd_m=args.imd_m,
            x_apple_imd_rinfo=args.imd_rinfo,
            baa_cert=args.baa_cert
        )
        
        # --- AQUÍ GUARDAMOS EL RESULTADO EN identity.plist ---
        ruta_plist = "identity.plist"
        with open(ruta_plist, "w", encoding="utf-8") as f:
            f.write(resultado)
            
        print("\n✅ Respuesta exitosa:")
        print(f"[Archivo guardado en: {os.path.abspath(ruta_plist)}]\n")
        print(resultado)
        
    except Exception as e:
        print(f"\n❌ Error de protocolo: {e}")

if __name__ == "__main__":
    asyncio.run(main())