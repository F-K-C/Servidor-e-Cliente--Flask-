from flask import Flask, request, jsonify
from crypto.encryptor import hybrid_encrypt

app = Flask(__name__)

@app.route("/encrypt", methods=["POST"])
def encrypt_message():
    try:
        # Recebe JSON do cliente
        data = request.get_json()
        plaintext = data.get("data", "")
        if not plaintext:
            return jsonify({"error": "Nenhuma mensagem fornecida"}), 400

        # Chama a função de criptografia híbrida
        result = hybrid_encrypt(plaintext)

        # Retorna o resultado em JSON
        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Executa servidor Flask na porta 3030
    app.run(host="0.0.0.0", port=3030, debug=True)
