import os
from flask import Flask, request, jsonify, render_template  # added render_template
from analyzer import analyze_log

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


@app.route("/")
def index():
    return render_template("index.html")  # now serves the HTML page


@app.route("/upload", methods=["POST"])
def upload_log():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    alerts = analyze_log(filepath)

    return jsonify({
        "message": "File uploaded and analyzed",
        "filename": file.filename,
        "alerts_found": len(alerts),
        "alerts": alerts
    }), 200


if __name__ == "__main__":
    app.run(debug=True)