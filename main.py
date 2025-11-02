from flask import Flask, request, jsonify
import base64

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])

def receive_message():
    data = request.get_json()
    text = data.get("data", "")
    text_bytes = text.encode("utf-8")
    text_b64 = base64.b64encode(text_bytes).decode("utf-8")

    return jsonify({"Mensagem codificada em base64": text_b64, "status": "ok"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=3030)