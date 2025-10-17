import os
import time
import logging
import requests
from flask import Flask, request, jsonify
from threading import Thread
from scapy.all import sniff, AsyncSniffer

# ==============================
#   ENVIRONMENT CONFIGURATION
# ==============================
os.environ["SCAPY_USE_PCAP"] = "yes"  # avoid DNS starvation due to raw sockets

MODE = os.getenv("MODE", "LIVE")
SERVICE_PORT = int(os.getenv("SERVICE_PORT", 5004))
PARSER_URL = os.getenv("PARSER_URL", "http://127.0.0.1:5001")
RUNTIME = os.getenv("RUNTIME", "docker")

HOST_IFACE_ENV = os.getenv("HOST_IFACE")          # e.g. enp39s0 (EC2 host)
POD_IFACE_ENV = os.getenv("POD_IFACE", "eth0")    # default pod interface

# ==============================
#   LOGGING CONFIGURATION
# ==============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

app = Flask(__name__)

sniffer = None
sniffing_active = False

# ==============================
#   CORE PACKET LOGIC
# ==============================

def send_packet(pkt, source="LIVE"):
    """Send captured packet summary and raw data to parser service."""
    data = {
        "raw": pkt.summary(),
        "hex": bytes(pkt).hex(),
        "source": source
    }

    try:
        requests.post(PARSER_URL, json=data, timeout=3)
    except requests.exceptions.RequestException as e:
        logging.warning(f"🌐 Transient send error, retrying: {e}")
        time.sleep(1)
        try:
            requests.post(PARSER_URL, json=data, timeout=3)
        except Exception as e2:
            logging.error(f"❌ Final failure sending to parser: {e2}")


def sniff_packets_live(iface_list):
    """Start live packet sniffing on the given interfaces."""
    global sniffer, sniffing_active
    sniffing_active = True

    def _sniff():
        logging.info(f"🚀 Starting sniffing on iface(s)={iface_list} mode={MODE}")
        try:
            sniffer = AsyncSniffer(iface=iface_list, prn=lambda p: send_packet(p, "LIVE"), store=False)
            sniffer.start()
            sniffer.join()
        except Exception as e:
            logging.error(f"❌ Sniffing error: {e}")

    t = Thread(target=_sniff, daemon=True)
    t.start()


def stop_sniffing():
    """Stop the sniffer gracefully."""
    global sniffer, sniffing_active
    if sniffer and sniffing_active:
        sniffer.stop()
        sniffing_active = False
        logging.info("🛑 Sniffer stopped")
    else:
        logging.warning("⚠️ Sniffer not running")


# ==============================
#   INTERFACE DETECTION LOGIC
# ==============================

def detect_interfaces():
    """Determine which network interfaces to sniff."""
    detected_iface = None
    try:
        for iface in os.listdir("/sys/class/net"):
            if iface not in ("lo", "docker0"):
                detected_iface = iface
                break
        logging.info(f"🧠 Host-level NIC detected via /sys/class/net: {detected_iface}")
    except Exception as e:
        logging.error(f"❌ Could not auto-detect interface: {e}")

    # Prefer environment overrides if available
    host_iface = HOST_IFACE_ENV or detected_iface
    pod_iface = POD_IFACE_ENV

    logging.info(f"✅ HOST_IFACE={host_iface}, POD_IFACE={pod_iface}")
    return [host_iface, pod_iface] if pod_iface else [host_iface]


# ==============================
#   FLASK ROUTES
# ==============================

@app.route("/start_sniffing", methods=["POST"])
def start_sniffing_api():
    global sniffing_active
    if sniffing_active:
        logging.warning("⚠️ Sniffer already running, ignoring duplicate start")
        return jsonify({"status": "already running"}), 200

    iface_list = detect_interfaces()
    sniff_packets_live(iface_list)
    return jsonify({"status": "sniffing started", "interfaces": iface_list})


@app.route("/stop_sniffing", methods=["POST"])
def stop_sniffing_api():
    stop_sniffing()
    return jsonify({"status": "stopped"})


@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "status": "running" if sniffing_active else "stopped",
        "mode": MODE,
        "parser_url": PARSER_URL
    })


# ==============================
#   MAIN ENTRYPOINT
# ==============================
if __name__ == "__main__":
    iface_list = detect_interfaces()
    logging.info(f"🧠 K8s runtime detected — forcing raw socket sniffing (bypassing Scapy)" if RUNTIME == "k8s" else "🧠 Running in Docker mode")
    logging.info(f"⚡ Using sniffing interfaces: {iface_list}")

    app.run(host="0.0.0.0", port=SERVICE_PORT)
