from flask import Flask, request

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    password = request.form.get("password")
    api_key = request.form.get("api_key")

    print("Received password:", password)
    print("Received API key:", api_key)

    return "Login request received successfully", 200

@app.route("/")
def home():
    return "HTTP test server is running", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)