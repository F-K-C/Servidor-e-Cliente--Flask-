import os
import json
from crypto.openssl_utils import OpenSSLCLI
from crypto.encryptor import HybridEncryptor

# Paths
BASE_DIR = os.path.dirname(__file__)
POLICY_PATH = os.path.join(BASE_DIR, "policy", "policy_pqc.json")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

# Carrega política
with open(POLICY_PATH, "r", encoding="utf-8") as f:
    policy = json.load(f)

# Inicializa OpenSSL CLI
openssl_cli = OpenSSLCLI()

# Tenta criar o encryptor
try:
    encryptor = HybridEncryptor(policy=policy, keys_dir=KEYS_DIR, openssl=openssl_cli)
    print("Encryptor inicializado com sucesso!")
except Exception as e:
    print("Erro ao inicializar encryptor:", str(e))
