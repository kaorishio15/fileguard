import sys
from flask import Flask, render_template, request, jsonify
from engine import analyze_file

app = Flask(__name__)

@app.route("/")
def index():
    # render main frontend interface
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan_api():
    # ensure file was included in the request
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    # run the analysis engine on uploaded bytes
    report = analyze_file(f.read(), f.filename)
    return jsonify(report)

if __name__ == "__main__":
    # support cli mode: python app.py scan <filename>
    if len(sys.argv) > 2 and sys.argv[1] == "scan":
        filepath = sys.argv[2]
        with open(filepath, "rb") as f:
            res = analyze_file(f.read(), filepath)
        print(f"\n--- FileGuard Analysis ---")
        print(f"File:      {res['filename']}")
        print(f"SHA-256:    {res['sha256']}")
        print(f"Risk Score: {res['risk_score']} / 100 ({res['severity']})")
        print(f"Indicators: {len(res['indicators'])}")
        for ind in res['indicators']:
            print(f"  - [{ind['rule']}] (+{ind['points']} pts): {ind['evidence']}")
    else:
        # run flask web server locally
        app.run(port=5000, debug=True)