import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.openssl_utils import OpenSSLCLI


class HybridEncryptor:
    def __init__(self, policy: dict, keys_dir: str, openssl: OpenSSLCLI = None):
        self.policy = policy
        self.keys_dir = Path(keys_dir)
        self.openssl = openssl or OpenSSLCLI()
        self._ensure_keys_dir()

    def _ensure_keys_dir(self):
        self.keys_dir.mkdir(parents=True, exist_ok=True)

    # --- PQC Keypair ---
    def _gen_pqc_keypair(self, alg_name: str, priv_path: Path, pub_path: Path):
        cmd = ["genpkey", "-algorithm", alg_name, "-out", str(priv_path)]
        self.openssl.run(cmd)
        self.openssl.run(["pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)])

    # --- Classical Keypairs ---
    def _gen_classical_keypair_x25519(self, priv_path: Path, pub_path: Path):
        self.openssl.run(["genpkey", "-algorithm", "X25519", "-out", str(priv_path)])
        self.openssl.run(["pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)])

    def _gen_classical_keypair_x448(self, priv_path: Path, pub_path: Path):
        self.openssl.run(["genpkey", "-algorithm", "X448", "-out", str(priv_path)])
        self.openssl.run(["pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)])

    def _gen_classical_keypair_rsa(self, priv_path: Path, pub_path: Path, key_size=2048):
        self.openssl.run([
            "genpkey",
            "-algorithm", "RSA",
            "-out", str(priv_path),
            "-pkeyopt", f"rsa_keygen_bits:{key_size}"
        ])
        self.openssl.run(["pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)])

    # --- KEM Encapsulation ---
    def _encapsulate_kem(self, pubkey_path: Path, kem_ct_path: Path, shared_secret_path: Path):
        if not self.openssl.has_pkeyutl_encap():
            raise RuntimeError("OpenSSL pkeyutl -encap not available.")
        self.openssl.run([
            "pkeyutl",
            "-encap",
            "-inkey", str(pubkey_path),
            "-out", str(kem_ct_path),
            "-secret", str(shared_secret_path)
        ])

    def _decapsulate_kem(self, privkey_path: Path, kem_ct_path: Path, shared_secret_path: Path):
        if not self.openssl.has_pkeyutl_encap():
            raise RuntimeError("OpenSSL pkeyutl -decap not available.")
        self.openssl.run([
            "pkeyutl",
            "-decap",
            "-inkey", str(privkey_path),
            "-in", str(kem_ct_path),
            "-secret", str(shared_secret_path)
        ])

    # --- HKDF Derivation ---
    @staticmethod
    def _derive_key_hkdf(shared_secret: bytes, length: int = 32, salt: bytes = b"", info: bytes = b"hybrid-key"):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info)
        return hkdf.derive(shared_secret)

    # --- AES-GCM ---
    @staticmethod
    def _aes_gcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes):
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # --- Encrypt Message ---
    def encrypt_message(self, plaintext: bytes):
        pqc_alg = self.policy.get("pqc_kem")
        classical = self.policy.get("classical_kex", "X25519")
        sym = self.policy.get("symmetric", {})
        key_len = sym.get("key_len", 32)
        nonce_len = sym.get("nonce_len", 12)

        pqc_priv = self.keys_dir / "pqc_priv.pem"
        pqc_pub = self.keys_dir / "pqc_pub.pem"
        classical_priv = self.keys_dir / "classical_priv.pem"
        classical_pub = self.keys_dir / "classical_pub.pem"

        if not pqc_priv.exists() or not pqc_pub.exists():
            self._gen_pqc_keypair(pqc_alg, pqc_priv, pqc_pub)

        classical_upper = classical.upper()
        if classical_upper == "X25519":
            if not classical_priv.exists() or not classical_pub.exists():
                self._gen_classical_keypair_x25519(classical_priv, classical_pub)
        elif classical_upper == "X448":
            if not classical_priv.exists() or not classical_pub.exists():
                self._gen_classical_keypair_x448(classical_priv, classical_pub)
        elif classical_upper == "RSA":
            if not classical_priv.exists() or not classical_pub.exists():
                self._gen_classical_keypair_rsa(classical_priv, classical_pub)
        else:
            raise NotImplementedError(f"Classical key type '{classical}' not implemented.")

        kem_ct = self.keys_dir / "kem_ct.bin"
        shared_secret_file = self.keys_dir / "shared_secret.bin"
        self._encapsulate_kem(pqc_pub, kem_ct, shared_secret_file)
        shared_secret = shared_secret_file.read_bytes()

        sym_key = self._derive_key_hkdf(shared_secret, length=key_len)
        nonce = os.urandom(nonce_len)
        ciphertext = self._aes_gcm_encrypt(sym_key, plaintext, nonce)

        result = {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "kem_ciphertext": base64.b64encode(kem_ct.read_bytes()).decode("utf-8"),
            "public_keys": {
                "pqc_pub": base64.b64encode(pqc_pub.read_bytes()).decode("utf-8"),
                "classical_pub": base64.b64encode(classical_pub.read_bytes()).decode("utf-8")
            }
        }
        return result

    # --- Decrypt Message ---
    def decrypt_message(self, kem_ciphertext_b64: str, nonce_b64: str, ciphertext_b64: str):
        kem_ct_bytes = base64.b64decode(kem_ciphertext_b64)
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        nonce_bytes = base64.b64decode(nonce_b64)

        kem_ct_file = self.keys_dir / "kem_ct_temp.bin"
        shared_secret_file = self.keys_dir / "shared_secret_temp.bin"
        kem_ct_file.write_bytes(kem_ct_bytes)

        pqc_priv = self.keys_dir / "pqc_priv.pem"
        self._decapsulate_kem(pqc_priv, kem_ct_file, shared_secret_file)

        shared_secret = shared_secret_file.read_bytes()
        sym = self.policy.get("symmetric", {})
        key_len = sym.get("key_len", 32)
        sym_key = self._derive_key_hkdf(shared_secret, length=key_len)

        aesgcm = AESGCM(sym_key)
        plaintext = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, associated_data=None)

        kem_ct_file.unlink(missing_ok=True)
        shared_secret_file.unlink(missing_ok=True)

        return plaintext.decode("utf-8")
