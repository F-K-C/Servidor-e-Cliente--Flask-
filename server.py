from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/send', methods=['POST'])
def receive_message():
    data = request.get_json()
    text = data.get("text", "")
    return jsonify({"received message": text, "status": "ok"})

if __name__ == "__main__":
    app.run(debug=True)