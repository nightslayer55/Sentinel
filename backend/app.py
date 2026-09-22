from flask import Flask, request, jsonify
from flask_cors import CORS

from analyzers.url_analyzer import analyze_url
from analyzers.qr_analyzer import decode_qr
from analyzers.message_analyzer import analyze_message

app = Flask(__name__)
CORS(app)


@app.get("/api/health")
def health():
    return jsonify({
        "status": "online",
        "service": "Sentinel"
    })


@app.post("/api/analyze/url")
def analyze_url_endpoint():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "error": "No URL provided"
        }), 400

    url = data["url"].strip()

    result = analyze_url(url)

    return jsonify(result)

@app.post("/api/analyze/qr")
def analyze_qr_endpoint():
    if "image" not in request.files:
        return jsonify({
            "error": "No QR image provided"
        }), 400

    image = request.files["image"]

    if image.filename == "":
        return jsonify({
            "error": "No image selected"
        }), 400

    temp_path = "temp_qr.png"
    image.save(temp_path)

    qr_result = decode_qr(temp_path)

    if not qr_result["success"]:
        return jsonify(qr_result), 400

    decoded_url = qr_result["data"]

    analysis = analyze_url(decoded_url)

    return jsonify({
        "qr": {
            "decoded": True,
            "data": decoded_url
        },
        "analysis": analysis
    })

@app.post("/api/analyze/message")
def analyze_message_endpoint():
    data = request.get_json()

    if not data or "message" not in data:
        return jsonify({
            "error": "No message provided"
        }), 400

    message = data["message"].strip()

    result = analyze_message(message)

    if not result["valid"]:
        return jsonify(result), 400

    analyses = []

    for url in result["urls"]:
        analyses.append({
            "url": url,
            "analysis": analyze_url(url)
        })

    return jsonify({
        "message": message,
        "url_count": len(result["urls"]),
        "analyses": analyses
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)