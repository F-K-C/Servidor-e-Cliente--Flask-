import os
import base64
from flask import Flask, request, jsonify
import json
from crypto.encryptor import HybridEncryptor
from crypto.openssl_utils import OpenSSLCLI

os.environ["OPENSSL_MODULES"] = os.path.expanduser("~/PQCnovo/oqs-provider/build/lib")
os.environ["PATH"] = os.path.expanduser("~/PQCnovo/openssl-3.5/bin") + ":" + os.environ.get("PATH", "")

print("[DEBUG] OPENSSL_MODULES =", os.environ["OPENSSL_MODULES"])
print("[DEBUG] PATH =", os.environ["PATH"])

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


@app.route("/encrypt_rsa", methods=["POST"])
def encrypt_rsa_route():
    data = request.get_json(force=True)
    plaintext = data.get("data", "")

    if not plaintext:
        return jsonify({"error": "empty data"}), 400

    try:
        # Arquivos temporários
        priv_key = os.path.join(KEYS_DIR, "rsa_temp_private.pem")
        pub_key = os.path.join(KEYS_DIR, "rsa_temp_public.pem")
        ciphertext_file = os.path.join(KEYS_DIR, "rsa_temp_cipher.bin")

        # 1. Gerar par RSA
        openssl_cli.run(["genpkey", "-algorithm", "RSA", "-out", priv_key, "-pkeyopt", "rsa_keygen_bits:3072"])
        openssl_cli.run(["rsa", "-in", priv_key, "-pubout", "-out", pub_key])

        # 2. Salvar plaintext temporariamente
        plaintext_path = os.path.join(KEYS_DIR, "rsa_temp_plain.txt")
        with open(plaintext_path, "w", encoding="utf-8") as f:
            f.write(plaintext)

        # 3. Criptografar RSA-OAEP
        openssl_cli.run([
            "pkeyutl",
            "-encrypt",
            "-inkey", pub_key,
            "-pubin",
            "-in", plaintext_path,
            "-out", ciphertext_file,
            "-pkeyopt", "rsa_padding_mode:oaep"
        ])

        # 4. Ler resultado
        with open(ciphertext_file, "rb") as f:
            ciphertext_bytes = f.read()
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("utf-8")

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "algorithm": "RSA-3072-OAEP",
        "ciphertext": ciphertext_b64
    })



@app.route("/decrypt_rsa", methods=["POST"])
def decrypt_rsa_route():
    data = request.get_json(force=True)
    ciphertext_b64 = data.get("ciphertext", "")

    if not ciphertext_b64:
        return jsonify({"error": "empty ciphertext"}), 400

    # Caminhos das chaves RSA temporárias
    priv_key = os.path.join(KEYS_DIR, "rsa_temp_private.pem")
    ciphertext_file = os.path.join(KEYS_DIR, "rsa_temp_cipher_input.bin")
    plaintext_file = os.path.join(KEYS_DIR, "rsa_temp_plain_output.txt")

    if not os.path.exists(priv_key):
        return jsonify({"error": "RSA private key not found. Run /encrypt_rsa first."}), 400

    try:
        # 1. Salvar ciphertext
        ciphertext = base64.b64decode(ciphertext_b64)
        with open(ciphertext_file, "wb") as f:
            f.write(ciphertext)

        # 2. Descriptografar com RSA-OAEP
        openssl_cli.run([
            "pkeyutl",
            "-decrypt",
            "-inkey", priv_key,
            "-in", ciphertext_file,
            "-out", plaintext_file,
            "-pkeyopt", "rsa_padding_mode:oaep"
        ])

        # 3. Ler plaintext
        with open(plaintext_file, "r", encoding="utf-8") as f:
            plaintext = f.read()

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "algorithm": "RSA-3072-OAEP",
        "plaintext": plaintext
    })


if __name__ == "__main__":
    app.run(port=3030, host="0.0.0.0", debug=True)
