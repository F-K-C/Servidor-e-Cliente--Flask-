import os
from flask import Flask, request, jsonify
import json
from crypto.encryptor import HybridEncryptor
from crypto.openssl_utils import OpenSSLCLI

os.environ["OPENSSL_MODULES"] = os.path.expanduser("~/PQCnovo/oqs-provider/build/lib")

BASE_DIR = os.path.dirname(__file__)
POLICY_PATH = os.path.join(BASE_DIR, "policy", "policy_pqc.json")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

# Load policy
with open(POLICY_PATH, "r", encoding="utf-8") as f:
    policy = json.load(f)

print(f"[DEBUG] KEM usado: {policy['pqc_kem']}, Algoritmo simétrico: {policy['symmetric']['algorithm']}")

openssl_cli = OpenSSLCLI() 
encryptor = HybridEncryptor(policy=policy, keys_dir=KEYS_DIR, openssl=openssl_cli)

app = Flask(__name__)

@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    data = request.get_json(force=True)
    plaintext = data.get("data", "")
    if not plaintext:
        return jsonify({"error": "empty data"}), 400
    try:
        result = encryptor.encrypt_message(plaintext.encode("utf-8"))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(result)

@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    data = request.get_json()
    if data is None:
        return jsonify({"error": "invalid JSON"}), 400

    kem_ct_b64 = data.get("kem_ciphertext")
    nonce_b64 = data.get("nonce")
    ciphertext_b64 = data.get("ciphertext")

    if not all([kem_ct_b64, nonce_b64, ciphertext_b64]):
        return jsonify({"error": "missing fields"}), 400

    try:
        plaintext = encryptor.decrypt_message(kem_ct_b64, nonce_b64, ciphertext_b64)
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("utf-8")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"plaintext": plaintext})


if __name__ == "__main__":
    app.run(port=3030, host="0.0.0.0", debug=True)
