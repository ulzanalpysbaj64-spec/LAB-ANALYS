"""Student portal (Lab 10). A small Flask program used to study its dependencies."""
import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)
REGISTRAR_URL = "https://registrar.example.edu/api/students/"


def load_settings(path="settings.yaml"):
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=yaml.FullLoader)


@app.route("/student/<int:student_id>")
def student(student_id):
    reply = requests.get(REGISTRAR_URL + str(student_id), timeout=5)
    return jsonify(reply.json())


@app.route("/settings", methods=["POST"])
def upload_settings():
    uploaded = request.files["settings"]    # form data is parsed by Werkzeug
    settings = yaml.load(uploaded.stream, Loader=yaml.FullLoader)
    return jsonify(sorted(settings))


if __name__ == "__main__":
    app.run(debug=True)
