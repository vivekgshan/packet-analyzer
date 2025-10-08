from flask import Flask, render_template, request, jsonify
import requests
from datetime import datetime
import pytz
from flask_cors import CORS
import logging
import os

app = Flask(__name__)
CORS(app)

# Analyzer + Capture endpoints
ANALYZER_URL = os.getenv("ANALYZER_URL", "http://analyzer-service:5003")
#CAPTURE_URL = "http://172.31.39.213:5004"
CAPTURE_URL = os.getenv("CAPTURE_URL",  "http://host.docker.internal:5004")


# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -------------------------------------------------------------------
# Filters for datetime formatting
# -------------------------------------------------------------------
@app.template_filter('to_datetime')
def to_datetime(value):
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None

@app.template_filter('to_ist')
def to_ist(value):
    try:
        tz = pytz.timezone('Asia/Kolkata')
        return value.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return value

# -------------------------------------------------------------------
# Start/Stop Sniffing APIs
# -------------------------------------------------------------------
@app.route("/api/start_sniffing", methods=["POST"])
def start_sniffing():
    try:
        iface = request.args.get("iface")  # may be None/empty
        url = f"{CAPTURE_URL}/start_sniffing"
        if iface:
            url += f"?iface={iface}"
        res = requests.post(url, timeout=5)
        logging.info(f"✅ Capture-service response: {res.json()}")
        return jsonify({"status": "started", "response": res.json()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/stop_sniffing", methods=["POST"])
def stop_sniffing():
    try:
        logging.info("🛑 Forwarding stop_sniffing request to capture-service...")
        res = requests.post(f"{CAPTURE_URL}/stop_sniffing")
        logging.info(f"✅ Capture-service response: {res.json()}")
        return jsonify({"status": "stopped", "response": res.json()})
    except Exception as e:
        logging.error(f"❌ Failed to stop sniffing: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/status", methods=["GET"])
def api_status():
    try:
        logging.info("ℹ️ Forwarding status request to capture-service...")
        res = requests.get(f"{CAPTURE_URL}/status")
        logging.info(f"✅ Capture-service status response: {res.json()}")
        return jsonify(res.json())
    except Exception as e:
        logging.error(f"❌ Failed to get status: {e}")
        return jsonify({"error": str(e)}), 500
# TOP: imports stay the same

# Add this endpoint to provide interface list to the UI
@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    try:
        # ask capture-service to enumerate (no new deps in UI image)
        r = requests.get(f"{CAPTURE_URL}/interfaces", timeout=3)
        return jsonify(r.json())
    except Exception:
        # safe fallback if capture not reachable
        return jsonify({"interfaces": [
            "eth0","eth1","ens3","ens4","ens5","ens6","ens7","ens8",
            "enp0s3","enp0s8","enp1s0","enp2s0","enp3s0","enp39s0",
            "eno1","eno2","bond0","en0","en1","awdl0","bridge0",
            "wlan0","wlp1s0","wlp2s0","wlp3s0","wlp4s0","lo"
        ]})


# -------------------------------------------------------------------
# UI Route
# -------------------------------------------------------------------
@app.route("/")
def index():
    protocol = request.args.get("protocol")
    source = request.args.get("source")
    packets, summary = [], {}
    try:
        summary = requests.get(f"{ANALYZER_URL}/protocol_summary").json()
        params = {}
        if source:
            params["source"] = source
        if protocol:
            packets = requests.get(f"{ANALYZER_URL}/filter?protocol={protocol}", params=params).json()
        else:
            packets = requests.get(f"{ANALYZER_URL}/packets", params=params).json()
    except Exception as e:
        logging.error(f"UI Error fetching analyzer data: {e}")
    return render_template("index.html", packets=packets, summary=summary, selected=protocol, selected_source=source)

# -------------------------------------------------------------------
# JSON APIs
# -------------------------------------------------------------------
@app.route("/api/packets", methods=["GET"])
def api_packets():
    try:
        packets = requests.get(f"{ANALYZER_URL}/packets").json()
        return jsonify({"limit": 50, "packets": packets})
    except Exception as e:
        logging.error(f"Error in /api/packets: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/summary", methods=["GET"])
def api_summary():
    try:
        summary = requests.get(f"{ANALYZER_URL}/protocol_summary").json()
        return jsonify(summary)
    except Exception as e:
        logging.error(f"Error in /api/summary: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/filter", methods=["GET"])
def api_filter():
    protocol = request.args.get("protocol")
    source = request.args.get("source")
    if not protocol:
        return jsonify({"error": "Missing 'protocol' parameter"}), 400
    try:
        params = {}
        if source:
            params["source"] = source
        packets = requests.get(f"{ANALYZER_URL}/filter?protocol={protocol}", params=params).json()
        return jsonify(packets)
    except Exception as e:
        logging.error(f"Error in /api/filter: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/all_protocols", methods=["GET"])
def api_all_protocols():
    try:
        packets = requests.get(f"{ANALYZER_URL}/all_protocols").json()
        return jsonify(packets)
    except Exception as e:
        logging.error(f"Error in /api/all_protocols: {e}")
        return jsonify({"error": str(e)}), 500

# -------------------------------------------------------------------
# Health Check
# -------------------------------------------------------------------
@app.route("/health")
def health():
    return "OK", 200

# -------------------------------------------------------------------
# Entrypoint
# -------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
