import os
import json
import base64
import tempfile
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

    def _gen_pqc_keypair(self, alg_name: str, priv_path: Path, pub_path: Path):
        """
        Attempt to generate PQC keypair via openssl genpkey (requires oqs-provider)
        alg_name: e.g. 'kyber512'
        """
        cmd = ["genpkey", "-algorithm", alg_name, "-out", str(priv_path)]
        # some providers may require -pkeyopt or other flags; keep it simple
        self.openssl.run(cmd)
        # export public key
        self.openssl.run(["pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)])

    def _gen_classical_keypair_x25519(self, priv_path: Path, pub_path: Path):
        # X25519 via genpkey
        self.openssl.run(["genpkey", "-algorithm", "X25519", "-out", str(priv_path)])
        self.openssl.run(["pkey", "-in", str(priv_path), "-pubout", "-out", str(pub_path)])

    def _encapsulate_kem(self, pubkey_path: Path, kem_ct_path: Path, shared_secret_path: Path):
        """
        Use 'openssl pkeyutl -encap' to produce encapsulated ciphertext and shared secret.
        Requires OpenSSL + oqs-provider support.
        """
        if not self.openssl.has_pkeyutl_encap():
            raise RuntimeError("OpenSSL pkeyutl -encap not available in this environment.")
        # pkeyutl -encap -inkey <pub> -peerkey not needed for some providers -out enc.bin -secretout secret.bin
        # Use -out for ciphertext and -secretout for raw shared secret
        self.openssl.run(["pkeyutl", "-encap", "-inkey", str(pubkey_path), "-out", str(kem_ct_path), "-secret", str(shared_secret_path)])

    def _derive_key_hkdf(self, shared_secret: bytes, length: int = 32, salt: bytes = b"", info: bytes = b"hybrid-key"):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info)
        return hkdf.derive(shared_secret)

    def _aes_gcm_encrypt(self, key: bytes, plaintext: bytes, nonce: bytes):
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        # AESGCM from cryptography returns ciphertext || tag (tag appended at end)
        return ct

    def encrypt_message(self, plaintext: bytes):
        # 1) read policy
        pqc_alg = self.policy.get("pqc_kem")
        classical = self.policy.get("classical_kex", "X25519")
        sym = self.policy.get("symmetric", {})
        key_len = sym.get("key_len", 32)
        nonce_len = sym.get("nonce_len", 12)

        # file paths
        pqc_priv = self.keys_dir / "pqc_priv.pem"
        pqc_pub = self.keys_dir / "pqc_pub.pem"
        dh_priv = self.keys_dir / "dh_priv.pem"
        dh_pub = self.keys_dir / "dh_pub.pem"

        # 2) generate keys if not present
        if not pqc_priv.exists() or not pqc_pub.exists():
            self._gen_pqc_keypair(pqc_alg, pqc_priv, pqc_pub)

        if classical.upper() == "X25519":
            if not dh_priv.exists() or not dh_pub.exists():
                self._gen_classical_keypair_x25519(dh_priv, dh_pub)
        else:
            # placeholder: RSA, etc. Could generate RSA here.
            raise NotImplementedError("Classical key type not implemented in this template.")

        # 3) encapsulate KEM: produce kem ciphertext and shared secret
        kem_ct = self.keys_dir / "kem_ct.bin"
        shared_secret_file = self.keys_dir / "shared_secret.bin"
        self._encapsulate_kem(pqc_pub, kem_ct, shared_secret_file)

        shared_secret = shared_secret_file.read_bytes()

        # 4) derive symmetric key via HKDF
        sym_key = self._derive_key_hkdf(shared_secret, length=key_len)

        # 5) AES-GCM encrypt
        import os
        nonce = os.urandom(nonce_len)
        ciphertext = self._aes_gcm_encrypt(sym_key, plaintext, nonce)

        # 6) prepare public keys (return pqc public key and dh public key)
        pqc_pub_b64 = base64.b64encode(pqc_pub.read_bytes()).decode("utf-8")
        dh_pub_b64 = base64.b64encode(dh_pub.read_bytes()).decode("utf-8")

        # read kem ciphertext bytes
        kem_ct_b = kem_ct.read_bytes()

        result = {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "kem_ciphertext": base64.b64encode(kem_ct_b).decode("utf-8"),
            "public_keys": {
                "pqc_pub": pqc_pub_b64,
                "classical_pub": dh_pub_b64
            }
        }
        return result
    
    def _decapsulate_kem(self, privkey_path: Path, kem_ct_path: Path, shared_secret_path: Path):
        """
        Decapsula o KEM usando a chave privada.
        """
        if not self.openssl.has_pkeyutl_encap():
            raise RuntimeError("OpenSSL pkeyutl -encap/-decap não disponível neste ambiente.")
        self.openssl.run([
            "pkeyutl",
            "-decap",
            "-inkey", str(privkey_path),
            "-in", str(kem_ct_path),
            "-secret", str(shared_secret_path)
            ])
        
    def decrypt_message(self, kem_ciphertext_b64: str, nonce_b64: str, ciphertext_b64: str):
        # 1) salvar KEM ciphertext temporariamente
        kem_ct_bytes = base64.b64decode(kem_ciphertext_b64)
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        nonce_bytes = base64.b64decode(nonce_b64)

        kem_ct_file = self.keys_dir / "kem_ct_temp.bin"
        shared_secret_file = self.keys_dir / "shared_secret_temp.bin"
        kem_ct_file.write_bytes(kem_ct_bytes)

        # 2) decapsular KEM usando chave privada PQC
        pqc_priv = self.keys_dir / "pqc_priv.pem"
        self._decapsulate_kem(pqc_priv, kem_ct_file, shared_secret_file)

        # 3) derivar chave simétrica via HKDF
        shared_secret = shared_secret_file.read_bytes()
        sym = self.policy.get("symmetric", {})
        key_len = sym.get("key_len", 32)
        sym_key = self._derive_key_hkdf(shared_secret, length=key_len)

        # 4) AES-GCM decrypt
        aesgcm = AESGCM(sym_key)
        plaintext = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, associated_data=None)

        # 5) limpar arquivos temporários
        kem_ct_file.unlink(missing_ok=True)
        shared_secret_file.unlink(missing_ok=True)

        return plaintext.decode("utf-8")

