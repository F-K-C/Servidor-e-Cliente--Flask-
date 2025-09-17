from flask import Flask, request, jsonify
import base64
import subprocess
import tempfile
import os

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])

def receive_message():
    data = request.get_json()
    text = data.get("data", "")
    text_bytes = text.encode("utf-8")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            pubkey_file = os.path.join(tmpdir, "pubkey.pem")
            subprocess.run(["openssl", "pkey", "-algorithm", "Kyber512", "-out", pubkey_file], check=True)

            result = subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pubkey_file], input=text_bytes, capture_output=True, check=True)
            ciphertext = result.stdout

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Falha na criptografia: {e}", "status":"fail"}), 500

    text_b64 = base64.b64encode(ciphertext).decode("utf-8")

    return jsonify({"encoded message": text_b64, "status": "ok"})

if __name__ == "__main__":
    app.run(debug=True, port=3030)