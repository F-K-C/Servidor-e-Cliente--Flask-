# pq3_server/crypto/encryptor.py

import base64

def hybrid_encrypt(plaintext: str) -> dict:
    """
    Função stub para teste do endpoint /encrypt.
    Retorna dados fictícios em base64.
    """
    # Aqui simulamos criptografia com base64 para teste
    fake_ciphertext = base64.b64encode(plaintext.encode()).decode()
    fake_nonce = base64.b64encode(b"12345678").decode()
    fake_kem_ciphertext = base64.b64encode(b"kemdata").decode()
    fake_public_keys = base64.b64encode(b"pubkeys").decode()

    return {
        "ciphertext": fake_ciphertext,
        "nonce": fake_nonce,
        "kem_ciphertext": fake_kem_ciphertext,
        "public_keys": fake_public_keys
    }
