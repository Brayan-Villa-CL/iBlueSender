import json
import time
import struct
import base64
import hashlib
import hmac as hmac_mod
import plistlib as plist
from datetime import datetime, timezone
import requests
import urllib3
urllib3.disable_warnings()

import pbkdf2
from Crypto.Hash import SHA256
import srp._pysrp as srp
from base64 import b64encode
import emulated.nac
# SRP config matching Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

import re
import paramiko
from dataclasses import dataclass
from typing import Dict
import subprocess
import os
import sys
import uuid
from enum import Enum

from hardware import get_hardware_profile
DEFAULT_HARDWARE = get_hardware_profile()

MACOS_VERSION = "13.2.1"
MACOS_BUILD = "22D68"


# ==================== SERVER CONFIG ====================
PROVISION_SERVER = "http://51.195.221.19/provision.php"

# ---------------------------------------------------------------------------
# CRIPTOGRAFÍA IDS (Nativa en Python)
# ---------------------------------------------------------------------------
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

def get_ids_bag(key, proxy_dict=None):
    """Devuelve los endpoints reales de producción de Apple IDS."""
    bag_urls = {
        "id-authenticate-ds-id": "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS",
        "id-get-handles": "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/idsGetHandles",
        "id-register": "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register",
        "id-query": "https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query",
        "id-get-dependent-registrations": "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/getDependentRegistrations"
    }
    return bag_urls.get(key, "https://identity.ess.apple.com/")

def _ids_nonce_http():
    """Genera un nonce criptográfico de 16 bytes para la petición HTTP."""
    return os.urandom(16)

def _ids_build_payload(nonce: bytes, bag: str, uri: str, body: bytes, token: bytes):
    """
    Construye el buffer binario exacto que Apple espera que firmemos.
    Es la concatenación directa de: Token APNs + Bag + URI + Nonce + Body comprimido.
    """
    return token + bag.encode('utf-8') + uri.encode('utf-8') + nonce + body

def _ids_sign(key, payload: bytes):
    """
    Firma el payload usando la llave privada proporcionada.
    Maneja automáticamente llaves RSA (Push/Auth) y llaves EC P-256 (Identity).
    """
    if isinstance(key, rsa.RSAPrivateKey):
        # Las firmas de Auth y Push usan RSA con PKCS#1 v1.5 y SHA-256
        return key.sign(
            payload,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        # Las firmas de identidad de iMessage usan ECDSA P-256 con SHA-256
        return key.sign(
            payload,
            ec.ECDSA(hashes.SHA256())
        )
    else:
        raise TypeError("Tipo de llave no soportado para la firma IDS")
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

@dataclass
class BAAField:
    x_apple_baa_time: str
    x_apple_baa_cert: str
    x_apple_baa_sig: str
    x_apple_baa_sig_alt: str

# ==================== BAA SIGNER (HTTP) ====================
class IDSBAASigner:
    """Obtiene firmas BAA del servidor remoto."""
    
    @staticmethod
    def baa_headers(body_b64: str, query: str) -> BAAField:
        """
        Obtiene BAA headers del servidor.
        body_b64: body en base64 (ya gzip comprimido)
        query: string de query (ej: "com.ids-register")
        """
        try:
            resp = requests.post(
                PROVISION_SERVER,
                data={"body": body_b64, "query": query},
                timeout=15
            )
            data = resp.json()
            
            if not data.get("success"):
                print(f"[BAA] Error del servidor: {data}")
                return BAAField("", "", "", "")
            
            baa = data.get("data", {})
            return BAAField(
                x_apple_baa_time=baa.get("x-apple-baa-time", ""),
                x_apple_baa_cert=baa.get("x-apple-baa-cert", ""),
                x_apple_baa_sig=baa.get("x-apple-baa-sig", ""),
                x_apple_baa_sig_alt=baa.get("x-apple-baa-sig-alt", "")
            )
        except Exception as e:
            print(f"[BAA] Error: {e}")
            return BAAField("", "", "", "")

    @staticmethod
    def add_baa_signature(body: str, headers: Dict[str, str], query: str) -> None:
        if headers is None:
            raise ValueError("El diccionario de headers no puede ser nulo")

        baa = IDSBAASigner.baa_headers(body, query)

        headers["x-apple-baa-cert"] = baa.x_apple_baa_cert
        headers["x-apple-baa-time"] = baa.x_apple_baa_time
        headers["x-apple-baa-sig"] = baa.x_apple_baa_sig
        headers["x-apple-baa-sig-alt"] = baa.x_apple_baa_sig_alt
        headers["x-apple-i-device-type"] = "1"
        headers["x-apple-baa-version"] = "1"
        headers["x-apple-baa-header-source"] = "0"
        headers["x-apple-baa-supported"] = "1"


class AnisetteField(Enum):
    IMD = "X-Apple-I-MD"
    IMDM = "X-Apple-I-MD-M"
    RINFO = "X-Apple-I-MD-RINFO"
# ==================== ANISETTE (HTTP) ====================
class RemoteAnisetteProvider:
    """Obtiene Anisette del servidor remoto."""
    
    def __init__(self, server_url=PROVISION_SERVER):
        self.server_url = server_url
        self.rinfo = ""
        self._cache = None
        self._cache_time = 0
    
    def _fetch(self):
        """Obtiene anisette del servidor."""
        resp = requests.get(f"{self.server_url}?anisette", timeout=10)
        data = resp.json()
        self.rinfo = data.get("X-Apple-I-MD-RINFO", "")
        return data
    
    def get_otp(self):
        """Devuelve (IMD, IMDM)."""
        data = self._fetch()
        imd = data.get("X-Apple-I-MD", "")
        imdm = data.get("X-Apple-I-MD-M", "")
        self.rinfo = data.get("X-Apple-I-MD-RINFO", "")
        return imd, imdm
    
    def get_validation_data(self):
        """Obtiene ValidationData del servidor."""
        resp = requests.get(f"{self.server_url}?validation", timeout=10)
        data = resp.json()
        vd = data.get("validation_data", "")
        print(f"[VD] Obtenido: {vd[:40]}...")
        return vd

# ---------------------------------------------------------------------------
# Crypto helpers (matching gsa_login.py)
# ---------------------------------------------------------------------------
def _encrypt_password(password, salt, iterations):
    p = hashlib.sha256(password.encode("utf-8")).digest()
    return pbkdf2.PBKDF2(p, salt, iterations, SHA256).read(32)

def _create_session_key(usr, name):
    k = usr.get_session_key()
    if k is None:
        raise Exception("No SRP session key")
    return hmac_mod.new(k, name.encode(), hashlib.sha256).digest()

def _decrypt_cbc(usr, data):
    extra_data_key = _create_session_key(usr, "extra data key:")
    extra_data_iv = _create_session_key(usr, "extra data iv:")[:16]
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

# ---------------------------------------------------------------------------
# GSALogin
# ---------------------------------------------------------------------------
class GSALogin:
    GSA_URL = "https://gsa.apple.com/grandslam/GsService2"

    def __init__(self, email, password, hardware, anisette, push_token_hex=None, proxy_dict=None):
        self.email = email.lower()
        self.password = password
        self.hw = hardware
        self.anisette = anisette 
        self.push_token_hex = push_token_hex or ""
        self.client_id = str(uuid.uuid4())
        self.spd = None
        self._usr = None
        self._au = None
        self._identity_token = None
        self.proxy_dict = proxy_dict

    def _mme_client_info(self):
        return f"<iPad7,11> <iPhone OS;{MACOS_VERSION};{MACOS_BUILD}> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

    def _fetch_anisette_data(self):
        """Corrección: Usar la interfaz pública en vez de abrir un SSH propio."""
        imd, imdm = self.anisette.get_otp()
        rinfo = getattr(self.anisette, 'rinfo', '')
        return imd, imdm, rinfo

    def _build_headers(self, imd, imdm, rinfo):
        return {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/1568.100.1 Darwin/22.3.0",
            "X-Apple-I-Locale": "zh-Hans_US",
            "X-Apple-I-TimeZone": "Asia/Shanghai",
            "X-Apple-I-Client-Time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "X-Apple-I-DeviceUserMode": "0",
            "X-Apple-I-TimeZone-Offset": "28800",
            "X-Apple-I-MD": imd,
            "X-Apple-I-MD-M": imdm,
            "X-Apple-I-MD-RINFO": rinfo,
            "X-Apple-I-SRL-NO": self.hw["serial_number"],
            "X-Apple-I-MLB": self.hw["mlb"],
            "X-Apple-I-ROM": self.hw["rom"],
            "X-Mme-Device-Id": self.hw["hardware_uuid"],
            "X-MMe-Client-Info": self._mme_client_info(),
        }

    def _build_cpd(self, imd, imdm, rinfo):
        return {
            "AppleIDClientIdentifier": self.client_id,
            "X-Apple-I-Client-Time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "X-Apple-I-MD": imd,
            "X-Apple-I-MD-M": imdm,
            "X-Apple-I-MD-RINFO": rinfo,
            "X-Apple-I-SRL-NO": self.hw["serial_number"],
            "X-Apple-I-MLB": self.hw["mlb"],
            "X-Apple-I-ROM": self.hw["rom"],
            "X-Mme-Device-Id": self.hw["hardware_uuid"],
            "bootstrap": True,
            "capp": "Preferences",
            "ckgen": True,
            "icscrec": True,
            "loc": "en_US",
            "pbe": False,
            "prkgen": True,
            "svct": "iMessage",
        }

    def login(self):
        print("[GSA] Obteniendo Anisette para SRP Init...")
        imd, imdm, rinfo = self._fetch_anisette_data()
        headers = self._build_headers(imd, imdm, rinfo)
        cpd = self._build_cpd(imd, imdm, rinfo)

        self._usr = srp.User(self.email, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, A = self._usr.start_authentication()

        body = {
            "Header": {"Version": "1.0.1"},
            "Request": {
                "A2k": A,
                "cpd": cpd,
                "o": "init",
                "ps": ["s2k", "s2k_fo"],
                "u": self.email,
            },
        }

        print(f"[GSA] SRP init for {self.email}...")
        resp = requests.post(self.GSA_URL, headers=headers, data=plist.dumps(body), verify=False, timeout=15, proxies=self.proxy_dict)
        full_resp = plist.loads(resp.content)
        res = full_resp.get("Response", {})

        status = full_resp.get("Response", {}).get("Status", {})
        if status.get("ec", 0) != 0:
            raise Exception(f"GSA init error: {status.get('em', 'unknown')}")

        self._usr.p = _encrypt_password(self.password, res["s"], res["i"])
        M = self._usr.process_challenge(res["s"], res["B"])

        print("[GSA] Obteniendo Anisette fresco para SRP Complete...")
        imd2, imdm2, rinfo2 = self._fetch_anisette_data()
        headers2 = self._build_headers(imd2, imdm2, rinfo2)
        cpd2 = self._build_cpd(imd2, imdm2, rinfo2)

        body2 = {
            "Header": {"Version": "1.0.1"},
            "Request": {
                "M1": M,
                "c": res["c"],
                "cpd": cpd2,
                "o": "complete",
                "u": self.email,
            },
        }

        print("[GSA] SRP complete...")
        resp2 = requests.post(self.GSA_URL, headers=headers2, data=plist.dumps(body2), verify=False, timeout=15, proxies=self.proxy_dict)
        r = plist.loads(resp2.content)["Response"]

        if "M2" not in r:
            raise Exception(f"GSA login failed: {r.get('Status', {}).get('em', 'unknown error')}")

        self._usr.verify_session(r["M2"])
        if not self._usr.authenticated():
            raise Exception("SRP session verification failed")

        spd_raw = _decrypt_cbc(self._usr, r["spd"])
        PLIST_HEADER = b"<?xml version='1.0' encoding='UTF-8'?>\n<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n"
        self.spd = plist.loads(PLIST_HEADER + spd_raw)
        self._au = r.get("Status", {}).get("au", "")

        print(f"[GSA] Login succeeded. adsid={self.spd.get('adsid')}, au={self._au}")
        return self.spd

    @property
    def needs_2fa(self):
        return self._au == "trustedDeviceSecondaryAuth"

    def _get_identity_token(self):
        dsid = self.spd["adsid"]
        idms_token = self.spd["GsIdmsToken"]
        token = base64.b64encode(f"{dsid}:{idms_token}".encode()).decode()
        self._identity_token = token
        return token

    def request_2fa_device_code(self):
        identity_token = self._get_identity_token()
        print("[GSA] Obteniendo Anisette para 2FA Request...")
        imd, imdm, rinfo = self._fetch_anisette_data()
        headers = self._build_headers(imd, imdm, rinfo)
        
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        headers["X-Apple-Identity-Token"] = identity_token
        headers["X-Apple-I-ICSCREC"] = "true"
        headers["X-Apple-I-CDP-Circle-Status"] = "false"
        headers["X-Apple-I-PRK-Gen"] = "true"
        del headers["Content-Type"]

        print("[GSA] Requesting 2FA device code...")
        resp = requests.get("https://gsa.apple.com/auth/verify/trusteddevice", headers=headers, verify=False, timeout=15, proxies=self.proxy_dict)
        return resp.status_code == 200

    def submit_2fa_device_code(self, code):
        if not self._identity_token:
            self._get_identity_token()

        print("[GSA] Obteniendo Anisette para enviar 2FA Code...")
        imd, imdm, rinfo = self._fetch_anisette_data()
        headers = self._build_headers(imd, imdm, rinfo)
        
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json, text/javascript, */*; q=0.01"
        headers["X-Apple-Identity-Token"] = self._identity_token
        headers["X-Apple-I-ICSCREC"] = "true"
        headers["X-Apple-I-CDP-Circle-Status"] = "false"
        headers["X-Apple-I-PRK-Gen"] = "true"
        headers["Referer"] = "https://gsa.apple.com/"
        headers["Origin"] = "https://gsa.apple.com"
        headers["X-Apple-I-Referrer"] = "https://gsa.apple.com/auth/verify/trusteddevice"

        json_body = {"securityCode": {"code": str(code)}}

        print(f"[GSA] Submitting 2FA code: {code}")
        resp = requests.post("https://gsa.apple.com/auth/verify/trusteddevice/securitycode", headers=headers, json=json_body, verify=False, timeout=15, proxies=self.proxy_dict)

        if "X-Apple-GS-Token" not in resp.headers:
            raise Exception("2FA code rejected")

        pe_raw = base64.b64decode(resp.headers["X-Apple-PE-Token"]).decode('utf-8')
        pe_token = pe_raw.split(":")[1]

        if "com.apple.gs.idms.pet" not in self.spd["t"]:
            self.spd["t"]["com.apple.gs.idms.pet"] = {}
        self.spd["t"]["com.apple.gs.idms.pet"]["token"] = pe_token
        return pe_token

    def request_2fa_sms_code(self, phone_id="1"):
        """Envía código 2FA por SMS al número registrado"""
        identity_token = self._get_identity_token()
        print("[GSA] Obteniendo Anisette para SMS 2FA...")
        imd, imdm, rinfo = self._fetch_anisette_data()
        headers = self._build_headers(imd, imdm, rinfo)
        
        headers["Accept"] = "application/x-buddyml"
        headers["Content-Type"] = "application/x-plist"
        headers["X-Apple-Identity-Token"] = identity_token
        headers["X-Apple-I-ICSCREC"] = "true"
        headers["X-Apple-I-CDP-Circle-Status"] = "false"
        headers["X-Apple-I-PRK-Gen"] = "true"
        headers["Referer"] = "https://gsa.apple.com/auth/verify/trusteddevice"
        headers["X-Apple-I-Referrer"] = "https://gsa.apple.com/auth/verify/trusteddevice"
        
        body = f'''<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>serverInfo</key>
        <dict>
            <key>phoneNumber.id</key>
            <string>{phone_id}</string>
        </dict>
    </dict>
    </plist>'''
        
        print(f"[GSA] Requesting SMS code to phone ID: {phone_id}")
        resp = requests.post(
            "https://gsa.apple.com/auth/verify/phone/put?mode=sms&referrer=/auth/verify/trusteddevice",
            headers=headers,
            data=body,
            verify=False,
            timeout=15,
            proxies=self.proxy_dict
        )
        
        # Guardar crsc cookie si viene
        if "crsc" in resp.cookies:
            self._crsc = resp.cookies["crsc"]
        
        return resp.status_code == 200

    def submit_2fa_sms_code(self, code, phone_id="1"):
        """Envía el código SMS recibido"""
        if not self._identity_token:
            self._get_identity_token()
        
        print("[GSA] Obteniendo Anisette para enviar SMS code...")
        imd, imdm, rinfo = self._fetch_anisette_data()
        headers = self._build_headers(imd, imdm, rinfo)
        
        headers["Accept"] = "application/x-buddyml"
        headers["Content-Type"] = "application/x-plist"
        headers["X-Apple-Identity-Token"] = self._identity_token
        headers["X-Apple-I-ICSCREC"] = "true"
        headers["X-Apple-I-CDP-Circle-Status"] = "false"
        headers["X-Apple-I-PRK-Gen"] = "true"
        headers["Referer"] = "https://gsa.apple.com/auth/verify/phone/put"
        headers["X-Apple-I-Referrer"] = "https://gsa.apple.com/auth/verify/phone/put"
        
        # Agregar crsc cookie si existe
        if hasattr(self, '_crsc') and self._crsc:
            headers["Cookie"] = f"crsc={self._crsc}"
        
        body = f'''<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>securityCode.code</key>
        <string>{code}</string>
        <key>serverInfo</key>
        <dict>
            <key>mode</key>
            <string>sms</string>
            <key>phoneNumber.id</key>
            <string>{phone_id}</string>
            <key>phoneNumber.nonFTEU</key>
            <string>true</string>
        </dict>
    </dict>
    </plist>'''
        
        print(f"[GSA] Submitting SMS code: {code}")
        resp = requests.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put",
            headers=headers,
            data=body,
            verify=False,
            timeout=15,
            proxies=self.proxy_dict
        )
        
        if "X-Apple-GS-Token" not in resp.headers:
            raise Exception("SMS code rejected")
        
        pe_raw = base64.b64decode(resp.headers["X-Apple-PE-Token"]).decode('utf-8')
        pe_token = pe_raw.split(":")[1]
        
        if "com.apple.gs.idms.pet" not in self.spd["t"]:
            self.spd["t"]["com.apple.gs.idms.pet"] = {}
        self.spd["t"]["com.apple.gs.idms.pet"]["token"] = pe_token
        return pe_token

    def get_pet_token(self):
        t = self.spd.get("t", {}).get("com.apple.gs.idms.pet", {}).get("token")
        if not t:
            raise Exception("PET token not available. Complete 2FA first.")
        return t

# ---------------------------------------------------------------------------
# IDS Delegate Login
# ---------------------------------------------------------------------------
class IDSLoginDelegates:
    LOGIN_DELEGATES_URL = "https://setup.icloud.com/setup/prefpane/loginDelegates"

    def __init__(self, gsa: GSALogin, anisette: RemoteAnisetteProvider, proxy_dict=None):
        self.gsa = gsa
        self.anisette = anisette
        self.auth_token = None
        self.profile_id = None
        self.proxy_dict = proxy_dict

    def login(self):
        pet = self.gsa.get_pet_token()
        adsid = self.gsa.spd["adsid"]
        username = self.gsa.email

        md, md_m = self.anisette.get_otp()
        validation_data = self.anisette.get_validation_data()

        body = {
            "apple-id": username,
            "client-id": str(uuid.uuid4()),
            "delegates": {
                "com.apple.private.ids": {
                    "protocol-version": "4"
                }
            },
            "password": pet,
        }

        headers = {
            "Content-Type": "application/xml",
            "Accept-Encoding": "gzip",
            "User-Agent": f"com.apple.iCloudHelper/282 CFNetwork/1568.100.1 Darwin/22.3.0",
            "X-Mme-Client-Info": f"<iPad7,11> <iPhone OS;{MACOS_VERSION};{MACOS_BUILD}> <com.apple.iCloudHelper/282 (com.apple.Preferences/1112.96)>",
            "X-MMe-Nas-Qualify": validation_data,
            "X-Apple-ADSID": adsid,
            "X-Apple-I-MD": md,
            "X-Apple-I-MD-M": md_m,
            "X-Apple-I-MD-RINFO": getattr(self.anisette, 'rinfo', ''),
            "X-Apple-I-SRL-NO": self.gsa.hw["serial_number"],
            "X-Mme-Device-Id": self.gsa.hw["hardware_uuid"],
        }

        auth = (username, pet)

        print("[IDS] Calling loginDelegates...")
        resp = requests.post(self.LOGIN_DELEGATES_URL, headers=headers, data=plist.dumps(body), auth=auth, verify=False, timeout=30, proxies=self.proxy_dict)

        parsed = plist.loads(resp.content)
        if isinstance(parsed, dict) and parsed.get("status", -1) != 0:
            error = parsed.get("localizedError", parsed.get("description", "unknown"))
            raise Exception(f"loginDelegates failed: {error}")

        delegates = parsed.get("delegates", {})
        ids_delegate = delegates.get("com.apple.private.ids", {})
        
        ids_status = ids_delegate.get("status", -1)
        if ids_status != 0:
            msg = ids_delegate.get("status-message", "unknown")
            raise Exception(f"IDS delegate status {ids_status}: {msg}")

        service_data = ids_delegate.get("service-data", {})
        self.auth_token = service_data.get("auth-token")
        self.profile_id = service_data.get("profile-id")

        if not self.auth_token or not self.profile_id:
            raise Exception(f"Missing auth-token or profile-id in IDS delegate: {service_data}")

        print(f"[IDS] Got profile_id={self.profile_id}")
        print(f"[IDS] Got auth_token={self.auth_token[:20]}...")
        return self.auth_token, self.profile_id


# ---------------------------------------------------------------------------
# IDSAuthenticate 
# ---------------------------------------------------------------------------
class IDSAuthenticate:
    def __init__(self, auth_token, profile_id, proxy_dict=None):
        self.auth_token = auth_token
        self.profile_id = profile_id
        self.private_key = None 
        self.cert_der = None     
        self.proxy_dict = proxy_dict

    def authenticate(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        cn = hashlib.sha1(self.profile_id.encode()).hexdigest().upper()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        ).sign(self.private_key, hashes.SHA256(), default_backend())

        csr_der = csr.public_bytes(serialization.Encoding.DER)

        body = {
            "authentication-data": {"auth-token": self.auth_token},
            "csr": csr_der,
            "realm-user-id": self.profile_id,
        }

        url = get_ids_bag("id-authenticate-ds-id", proxy_dict=self.proxy_dict)
        version_ua = f"[macOS,{MACOS_VERSION},{MACOS_BUILD},iMac19,1]"

        import gzip as gzip_mod
        body_bytes = plist.dumps(body)
        body_gz = gzip_mod.compress(body_bytes)

        print(f"[IDS-Auth] Authenticating profile_id={self.profile_id}...")
        resp = requests.post(url, data=body_gz, headers={
            "user-agent": f"com.apple.invitation-registration {version_ua}",
            "x-protocol-version": "1660",
            "content-encoding": "gzip",
            "Content-Type": "application/x-apple-plist",
        }, verify=False, timeout=15, proxies=self.proxy_dict)

        parsed = plist.loads(resp.content)
        status = parsed.get("status", -1)
        if status != 0:
            raise Exception(f"IDS authenticate failed: status={status}, resp={parsed}")

        self.cert_der = bytes(parsed["cert"])
        print(f"[IDS-Auth] Got auth cert ({len(self.cert_der)} bytes)")
        return self.cert_der, self.private_key

# ---------------------------------------------------------------------------
# IDSIdentity 
# ---------------------------------------------------------------------------
class IDSIdentity:
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.signing_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.encryption_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1280,
            backend=default_backend()
        )

    def encode_public(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        ec_pub_bytes = self.signing_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )
        sig_data = struct.pack('>H', len(ec_pub_bytes)) + ec_pub_bytes

        rsa_pub_der = self.encryption_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1
        )
        enc_data = struct.pack('>H', len(rsa_pub_der)) + rsa_pub_der

        def _asn1_context_tag(tag_num, data):
            tag = 0x80 | tag_num  # ← CAMBIO: 0x80 en vez de 0xa0
            if len(data) < 128:
                return bytes([tag, len(data)]) + data
            elif len(data) < 256:
                return bytes([tag, 0x81, len(data)]) + data
            else:
                return bytes([tag, 0x82]) + struct.pack('>H', len(data)) + data

        inner = _asn1_context_tag(1, sig_data) + _asn1_context_tag(2, enc_data)

        if len(inner) < 128:
            seq = bytes([0x30, len(inner)]) + inner
        elif len(inner) < 256:
            seq = bytes([0x30, 0x81, len(inner)]) + inner
        else:
            seq = bytes([0x30, 0x82]) + struct.pack('>H', len(inner)) + inner

        return seq

# ---------------------------------------------------------------------------
# IDSRegister
# ---------------------------------------------------------------------------
MADRID_SUB_SERVICES = [
    "com.apple.private.alloy.sms",
    "com.apple.private.alloy.gelato",
    "com.apple.private.alloy.biz",
    "com.apple.private.alloy.gamecenter.imessage",
]
import gzip as gzip_mod
import base64
import struct
import os
import time
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

def generate_nonce() -> bytes:
    """Nonce 17 bytes: 0x01 || timestamp_ms_be(8) || 8 random"""
    ts_ms = int(time.time() * 1000)
    nonce = bytearray(17)
    nonce[0] = 0x01
    for i in range(7, -1, -1):
        nonce[1 + (7 - i)] = (ts_ms >> (8 * i)) & 0xFF
    nonce[9:17] = os.urandom(8)
    return bytes(nonce)

def create_payload(bag_key: str, query_string: str, push_token: bytes, payload: bytes, nonce: bytes = None) -> tuple:
    """Payload: nonce || bag_len(4) || bag || qs_len(4) || qs || payload_len(4) || payload || token_len(4) || token"""
    if nonce is None:
        nonce = generate_nonce()
    bag = bag_key.encode('utf-8') if bag_key else b''
    qs = query_string.encode('utf-8') if query_string else b''
    payload = payload or b''
    push_token = push_token or b''
    
    result = bytearray()
    result.extend(nonce)
    result.extend(struct.pack('>I', len(bag)))
    result.extend(bag)
    result.extend(struct.pack('>I', len(qs)))
    result.extend(qs)
    result.extend(struct.pack('>I', len(payload)))
    result.extend(payload)
    result.extend(struct.pack('>I', len(push_token)))
    result.extend(push_token)
    return bytes(result), nonce

def sign_rsa(key, bag_key: str, query_string: str, push_token: bytes, payload: bytes) -> tuple:
    """Firma SHA1withRSA + prefijo 0x01 0x01"""
    data, nonce = create_payload(bag_key, query_string, push_token, payload)
    sig = key.sign(data, asym_padding.PKCS1v15(), hashes.SHA1())
    final_sig = bytes([0x01, 0x01]) + sig
    return base64.b64encode(final_sig).decode(), nonce

class IDSRegister:
    def __init__(self, user_id, auth_cert_der, auth_private_key,
                 push_token_bytes, push_cert_der, push_private_key,
                 identity, anisette, hardware, proxy_dict=None):
        self.user_id = user_id
        self.auth_cert = auth_cert_der
        self.auth_key = auth_private_key
        self.push_token = push_token_bytes
        self.push_cert = push_cert_der
        self.push_key = push_private_key
        self.identity = identity
        self.anisette = anisette
        self.hw = hardware
        self.handles = []
        self.id_cert = None
        self.proxy_dict = proxy_dict

    def _get_private_device_data(self):
        apple_epoch_offset = 978307200
        d_val = time.time() - apple_epoch_offset
        return {
            "ap": "0", "d": f"{d_val:.6f}", "dt": 1, "gt": "0", "h": "1", "m": "0", "p": "0",
            "pb": MACOS_BUILD, "pn": "macOS", "pv": MACOS_VERSION, "s": "0", "t": "0",
            "u": self.hw["hardware_uuid"].upper(), "v": "1",
        }

    def _get_handles(self):
        bag_key = "id-get-handles"
        url = get_ids_bag(bag_key, proxy_dict=self.proxy_dict)

        # Firma push
        push_sig, push_nonce = sign_rsa(self.push_key, bag_key, "", self.push_token, b"")
        # Firma auth
        auth_sig, auth_nonce = sign_rsa(self.auth_key, bag_key, "", self.push_token, b"")

        headers = {
            "x-push-token": base64.b64encode(self.push_token).decode(),
            "x-protocol-version": "1660",
            "x-auth-user-id": self.user_id,
            "x-auth-nonce": base64.b64encode(auth_nonce).decode(),
            "x-auth-sig": auth_sig,
            "x-auth-cert": base64.b64encode(self.auth_cert).decode(),
            "x-push-nonce": base64.b64encode(push_nonce).decode(),
            "x-push-sig": push_sig,
            "x-push-cert": base64.b64encode(self.push_cert).decode(),
        }

        print(f"[IDS-Reg] Fetching handles for {self.user_id}...")
        resp = requests.get(url, headers=headers, verify=False, timeout=15, proxies=self.proxy_dict)
        parsed = plist.loads(resp.content)

        if parsed.get("status", -1) != 0:
            raise Exception(f"id-get-handles failed: {parsed}")

        return [h["uri"] for h in parsed.get("handles", [])]

    def register(self):
        import gzip as gzip_mod
        handles = self._get_handles()
        
        # 1. validation_data como BYTES
        vd_b64 = self.anisette.get_validation_data()
        validation_data = base64.b64decode(vd_b64)
        
        identity_key = self.identity.encode_public()
        
        # 2. Generar protobuf correctos (como en C#)
        ngm_prekey = self._generate_ngm_prekey_proto()
        kt_loggable = self._generate_kt_loggable_proto()

        client_data = {
            "ec-version": 1,
            "kt-version": 5,
            "nicknames-version": 1,
            "optionally-receive-typing-indicators": True,
            "prefers-sdr": False,
            "public-message-identity-key": identity_key,
            #"public-message-identity-ngm-version": 13,
            "public-message-identity-version": 2,
            #"public-message-ngm-device-prekey-data-key": ngm_prekey,
            "sender-key-message-version": 1,
            "show-peer-errors": True,
            "supports-ack-v1": True,
            "supports-animoji-v2": True,
            "supports-askto": True,
            "supports-audio-messaging-v2": True,
            "supports-autoloopvideo-v1": True,
            "supports-be-v1": True,
            "supports-ca-v1": True,
            "supports-certified-delivery-v1": True,
            "supports-cross-platform-sharing": True,
            "supports-dq-nr": True,
            "supports-emoji-images": True,
            "supports-emoji-stickers": True,
            "supports-emoji-tapbacks": True,
            "supports-family-invite-message-bubble": True,
            "supports-findmy-plugin-messages": True,
            "supports-fsm-v1": True,
            "supports-fsm-v2": True,
            "supports-fsm-v3": True,
            "supports-group-photo-refresh-version": 1,
            "supports-hdr": False,
            "supports-heif": True,
            "supports-high-quality-photo-file-sizes": True,
            "supports-hybrid-groups-v1": True,
            "supports-ii-v1": True,
            "supports-impact-v1": True,
            "supports-inline-attachments": True,
            "supports-keep-receipts": True,
            "supports-live-delivery": True,
            "supports-location-sharing": True,
            "supports-media-v2": True,
            "supports-original-timestamp-v1": True,
            "supports-people-request-messages": True,
            "supports-people-request-messages-v2": True,
            "supports-people-request-messages-v3": True,
            "supports-photos-extension-v1": True,
            "supports-photos-extension-v2": True,
            "supports-protobuf-payload-data-v2": True,
            "supports-qta": True,
            "supports-rbm-chatbot": True,
            "supports-recurring-payment-bubbles": True,
            "supports-rem": True,
            "supports-sa-v1": True,
            "supports-send-later-messages": True,
            "supports-sender-key-self-check": True,
            "supports-sender-key-v1": True,
            "supports-st-v1": True,
            "supports-stick-moji-backs": True,
            "supports-sticker-editing": True,
            "supports-update-attachments-v1": True,
            "supports-zelkova": True,
        }

        uris = [{"uri": f"mailto:{h}" if not h.startswith("mailto:") else h} for h in handles]

        user_data = {
            "client-data": client_data,
            "kt-loggable-data": kt_loggable,
            "kt-opt-absent": 9,
            "uris": uris,
            "user-id": self.user_id,
        }

        sub_services = [
            "com.apple.private.alloy.biz",
            "com.apple.private.alloy.sms",
            "com.apple.private.alloy.safetymonitor",
            "com.apple.madrid.lite",
            "com.apple.private.alloy.gelato",
            "com.apple.private.alloy.gamecenter.imessage",
            "com.apple.private.alloy.safetymonitor.ownaccount",
            "com.apple.private.alloy.askto",
            "com.apple.private.alloy.fitnessfriends.imessage",
        ]

        services = [{
            "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
            "service": "com.apple.madrid",
            "sub-services": sub_services,
            "users": [user_data],
        }]

        ios_version = "18.7.10"
        ios_build = "22H374"
        device_model = "iPad7,11"  # Fijo, no del hardware
        
        apple_epoch_offset = 978307200
        d_val = time.time() - apple_epoch_offset
        
        private_device_data = {
            "ap": "1",
            "c": "1",
            "d": f"{d_val:.6f}",
            "dt": 4,
            "ec": "1",
            "gt": "0",
            "h": "1",
            "ktf": "0",
            "ktv": 109,
            "m": "0",
            "p": "0",
            "pb": ios_build,
            "pn": "iPhone OS",
            "pv": ios_version,
            "s": "0",
            "t": "0",
            "u": "00008120-0004098A2642601E",  # UDID fijo o del device
            "v": "1",
        }

        version_ua = f"[iPhone OS,{ios_version},{ios_build},{device_model}]"
        
        body = {
            "device-name": "iPad",
            "hardware-version": device_model,
            "language": "es-MX",
            "os-version": f"iPhone OS,{ios_version},{ios_build}",
            "private-device-data": private_device_data,
            "retry-count": 0,
            "services": services,
            "software-version": ios_build,
            "validation-data": validation_data,  # BYTES
        }

        body_bytes = plist.dumps(body)
        body_gz = gzip_mod.compress(body_bytes)

        bag_key = "id-register"
        url = get_ids_bag(bag_key)

        push_sig, push_nonce = sign_rsa(self.push_key, bag_key, "", self.push_token, body_gz)
        auth_sig, auth_nonce = sign_rsa(self.auth_key, bag_key, "", self.push_token, body_gz)

        md, md_m = self.anisette.get_otp()
        rinfo = getattr(self.anisette, 'rinfo', '67437824')

        headers = {
            "x-auth-sig-0": auth_sig,
            "x-push-nonce": base64.b64encode(push_nonce).decode(),
            "Accept": "*/*",
            "X-Apple-I-Client-Time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "x-protocol-version": "1860",
            "Accept-Encoding": "gzip",
            "x-apple-req-reason": "v1:[1.1.0]",
            "User-Agent": f"com.apple.invitation-registration {version_ua}",
            "X-Apple-I-MD-M": md_m,
            "X-Apple-I-MD": md,
            "x-push-cert": base64.b64encode(self.push_cert).decode(),
            "X-Apple-I-Locale": "es_MX",
            "x-push-token": base64.b64encode(self.push_token).decode(),
            "Accept-Language": "es-MX,es-419;q=0.9,es;q=0.8",
            "x-auth-nonce-0": base64.b64encode(auth_nonce).decode(),
            "x-auth-cert-0": base64.b64encode(self.auth_cert).decode(),
            "X-Apple-I-TimeZone": "GMT-6",
            "Connection": "keep-alive",
            "Content-Type": "application/x-apple-plist",
            "x-auth-user-id-0": self.user_id,
            "X-Apple-I-MD-RINFO": rinfo,
            "x-push-sig": push_sig,
            "content-encoding": "gzip",
        }

        # BAA solo si funciona
        print("[IDS-Reg] Obteniendo BAA signature del servidor...")
        try:
            body_b64 = base64.b64encode(body_gz).decode()
            baa = IDSBAASigner.baa_headers(body_b64, "com.ids-register")
            if baa.x_apple_baa_sig:
                headers["x-apple-baa-cert"] = baa.x_apple_baa_cert
                headers["x-apple-baa-time"] = baa.x_apple_baa_time
                headers["x-apple-baa-sig"] = baa.x_apple_baa_sig
                headers["x-apple-baa-sig-alt"] = baa.x_apple_baa_sig_alt
                headers["x-apple-i-device-type"] = "1"
                headers["x-apple-baa-version"] = "1"
                headers["x-apple-baa-header-source"] = "1"
                headers["x-apple-baa-supported"] = "1"
                headers["x-apple-baa-ak-feature"] = "1"
                print(f"[IDS-Reg] BAA OK")
            else:
                print("[IDS-Reg] ⚠️ BAA no disponible")
        except Exception as e:
            print(f"[IDS-Reg] ⚠️ BAA error: {e}")

        print(f"[IDS-Reg] Registering...")
        
        resp = requests.post(url, data=body_gz, headers=headers, verify=False, timeout=30, proxies=self.proxy_dict)
        parsed = plist.loads(resp.content)

        if parsed.get("status", -1) != 0:
            raise Exception(f"IDS register failed: {parsed}")

        for svc in parsed.get("services", []):
            for u in svc.get("users", []):
                self.id_cert = bytes(u.get("cert", b""))
                for uri_entry in u.get("uris", []):
                    if uri_entry.get("status", -1) == 0:
                        self.handles.append(uri_entry.get("uri", ""))

        return self.handles

    def _generate_ngm_prekey_proto(self) -> bytes:
        """Genera NGM prekey con formato protobuf"""
        data = bytearray()
        data.extend(b'\x0a\x20')  # field 1, 32 bytes
        data.extend(os.urandom(32))
        data.extend(b'\x12\x41')  # field 2, 65 bytes
        data.extend(os.urandom(65))
        # Rellenar hasta ~800 bytes
        while len(data) < 800:
            chunk = os.urandom(min(64, 800 - len(data)))
            data.extend(chunk)
        return bytes(data[:800])

    def _generate_kt_loggable_proto(self) -> bytes:
        """Genera kt-loggable-data con formato protobuf"""
        data = bytearray()
        data.extend(b'\x0a\x24\x0a')  # CiQK
        data.extend(os.urandom(32))
        data.extend(b'\x10\x0d\x10\x05')  # EA0Q
        data.extend(os.urandom(4))
        data.extend(b'\x22\x45\x08\x01\x12\x41')  # IkUIARJB
        data.extend(os.urandom(64))
        return bytes(data)


def fetch_device_code(*args, **kwargs):
    """Solicita al usuario que ingrese manualmente el código 2FA en la terminal."""
    while True:
        code = input("[2FA] Ingresa el código de verificación de 6 dígitos (Apple ID): ").strip()
        
        # Validamos que solo contenga números y sean exactamente 6
        if code.isdigit() and len(code) == 6:
            print(f"[2FA] Código aceptado: {code}")
            return code
        else:
            print("[!] Código inválido. Por favor, asegúrate de ingresar exactamente 6 números.")

# ---------------------------------------------------------------------------
# Session Cache — save/load all credentials to skip re-login
# ---------------------------------------------------------------------------

SESSION_CACHE_PATH = 'tmp/session_cache.json'


class SessionCache:
    """Persist all login state to disk for session reuse."""

    @staticmethod
    def save(push_token_bytes, push_cert_der, push_key, auth_token, profile_id,
             adsid, auth_cert_der, auth_key, identity, handles, id_cert,
             hardware):
        from cryptography.hazmat.primitives.asymmetric import ec
        data = {
            'push_token': base64.b64encode(push_token_bytes).decode(),
            'auth_token': auth_token,
            'profile_id': profile_id,
            'adsid': adsid,
            'handles': handles,
            'id_cert': base64.b64encode(id_cert).decode() if id_cert else None,
            'auth_cert_der': base64.b64encode(auth_cert_der).decode(),
            'auth_key_pem': auth_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode(),
            'push_cert_der': base64.b64encode(push_cert_der).decode(),
            'push_key_pem': push_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode(),
            'identity_signing_key_pem': identity.signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode(),
            'identity_encryption_key_pem': identity.encryption_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ).decode(),
            'hardware': hardware,
            'saved_at': time.time(),
        }
        os.makedirs(os.path.dirname(SESSION_CACHE_PATH), exist_ok=True)
        with open(SESSION_CACHE_PATH, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[Cache] Session saved to {SESSION_CACHE_PATH}")

    @staticmethod
    def load():
        """Load cached session. Returns dict or None if not found/expired."""
        from cryptography.hazmat.primitives.asymmetric import ec
        if not os.path.exists(SESSION_CACHE_PATH):
            return None
        with open(SESSION_CACHE_PATH, 'r') as f:
            data = json.load(f)
        # Reconstruct crypto objects
        data['push_token_bytes'] = base64.b64decode(data['push_token'])
        data['auth_cert_der_bytes'] = base64.b64decode(data['auth_cert_der'])
        data['push_cert_der_bytes'] = base64.b64decode(data['push_cert_der'])
        data['id_cert_bytes'] = base64.b64decode(data['id_cert']) if data.get('id_cert') else None
        data['auth_key_obj'] = serialization.load_pem_private_key(
            data['auth_key_pem'].encode(), password=None)
        data['push_key_obj'] = serialization.load_pem_private_key(
            data['push_key_pem'].encode(), password=None)
        # Reconstruct IDSIdentity
        identity = IDSIdentity.__new__(IDSIdentity)
        identity.signing_key = serialization.load_pem_private_key(
            data['identity_signing_key_pem'].encode(), password=None)
        identity.encryption_key = serialization.load_pem_private_key(
            data['identity_encryption_key_pem'].encode(), password=None)
        data['identity_obj'] = identity
        print(f"[Cache] Session loaded from {SESSION_CACHE_PATH} (saved {time.ctime(data['saved_at'])})")
        return data


if __name__ == "__main__":
    import argparse
    import uuid
    from cryptography import x509 as x509mod
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    import os
    
    parser = argparse.ArgumentParser(description="iMessage Registration")
    parser.add_argument("-e", "--email", required=True, help="Apple ID email")
    parser.add_argument("-p", "--password", required=True, help="Apple ID password")
    parser.add_argument("--code-url", default="", help="URL para obtener código 2FA")
    args = parser.parse_args()
    
    # === SKIP si ya existen los archivos ===
    apns_cert_path = "tmp/apns_certificate.pem"
    apns_key_path = "tmp/apns_private_key.pem"
    
    if os.path.exists(apns_cert_path) and os.path.exists(apns_key_path):
        print("[*] APNS certificate and private key already exist, skipping generation.")
    else:
        print("[*] Generating APNS certificate...")
        albert_activation.gen_apns_cert()
    
    EMAIL = args.email
    PASSWORD = args.password
    CODE_URL = args.code_url
    
    hw = DEFAULT_HARDWARE.copy()

    print("\n" + "=" * 60)
    print("STEP 2: Anisette (Remote Server)")
    print("=" * 60)
    
    # === USAR SERVIDOR REMOTO ===
    anisette = RemoteAnisetteProvider()
    print("[+] Usando servidor remoto para Anisette/BAA/VD")
    
    # Verificar conexión
    imd, imdm = anisette.get_otp()
    if imd:
        print(f"[+] Anisette OK: {imd[:20]}...")
    else:
        print("[!] Error obteniendo Anisette")
        sys.exit(1)

    # === TOKEN DEL DISPOSITIVO ===
    DEVICE_PUSH_TOKEN_B64 = "ss31yJwn7oJD0RdMO+4aCnvN+gG7qJ1su+vRVjkAxzI="
    push_token_bytes = base64.b64decode(DEVICE_PUSH_TOKEN_B64)
    push_token_hex = push_token_bytes.hex()

    print(f"[*] Push token: {push_token_hex[:16]}...")
        
    print("\n" + "=" * 60)
    print("STEP 3: GSA SRP Login")
    print("=" * 60)
    gsa = GSALogin(EMAIL, PASSWORD, hw, anisette, push_token_hex)
    spd = gsa.login()

    if gsa.needs_2fa:
        print("\n" + "=" * 60)
        print("STEP 4: 2FA Verification")
        print("=" * 60)
        
        method = input("[?] Método 2FA (1=Device Code, 2=SMS): ").strip()
        
        if method == "2":
            phone_id = input("[?] Phone ID (default=1): ").strip() or "1"
            gsa.request_2fa_sms_code(phone_id)
            code = input("[?] Código SMS: ").strip()
            gsa.submit_2fa_sms_code(code, phone_id)
        else:
            gsa.request_2fa_device_code()
            code = fetch_device_code()
            gsa.submit_2fa_device_code(code)
    else:
        pet = spd.get("t", {}).get("com.apple.gs.idms.pet", {}).get("token")
        if pet:
            print(f"[+] PET token already present (no 2FA needed)")
        else:
            print(f"[!] No 2FA required but no PET token found.")
    
    print("\n" + "=" * 60)
    print("STEP 5: IDS loginDelegates")
    print("=" * 60)
    ids_delegate = IDSLoginDelegates(gsa, anisette)
    auth_token, profile_id = ids_delegate.login()
    
    print("\n" + "=" * 60)
    print("STEP 6: IDS Authenticate (get auth cert)")
    print("=" * 60)
    ids_auth = IDSAuthenticate(auth_token, profile_id)
    auth_cert_der, auth_private_key = ids_auth.authenticate()

    print("\n" + "=" * 60)
    print("STEP 7: IDS Register (iMessage)")
    print("=" * 60)

    with open('tmp/apns_certificate.pem', 'rb') as f:
        push_cert_obj = x509mod.load_pem_x509_certificate(f.read(), default_backend())
    push_cert_der = push_cert_obj.public_bytes(serialization.Encoding.DER)
    
    with open('tmp/apns_private_key.pem', 'rb') as f:
        push_private_key = serialization.load_pem_private_key(f.read(), password=None)

    identity = IDSIdentity()
    ids_reg = IDSRegister(
        user_id=profile_id,
        auth_cert_der=auth_cert_der,
        auth_private_key=auth_private_key,
        push_token_bytes= push_token_bytes,
        push_cert_der=push_cert_der,
        push_private_key=push_private_key,
        identity=identity,
        anisette=anisette,
        hardware=hw,
    )
    registered_handles = ids_reg.register()
    SessionCache.save(
        push_token_bytes=push_token_bytes,
        push_cert_der=push_cert_der,
        push_key=push_private_key,
        auth_token=auth_token,
        profile_id=profile_id,
        adsid=spd.get('adsid', ''),
        auth_cert_der=auth_cert_der,
        auth_key=auth_private_key,
        identity=identity,
        handles=registered_handles,
        id_cert=ids_reg.id_cert,
        hardware=hw,
    )

    print("\n" + "=" * 60)
    print("RESULT")
    print("=" * 60)
    print(f"  push_token:  {push_token_hex}")
    print(f"  profile_id:  {profile_id}")
    print(f"  adsid:       {spd.get('adsid')}")
    print(f"  handles:     {registered_handles}")
    print(f"  id_cert:     {len(ids_reg.id_cert)} bytes" if ids_reg.id_cert else "  id_cert:     None")
    print("[+] Phase 3 complete — iMessage registered. Session cached.")
