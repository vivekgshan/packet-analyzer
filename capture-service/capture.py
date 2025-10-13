from flask import Flask, request, jsonify
from scapy.all import AsyncSniffer, rdpcap
from scapy.utils import PcapReader
import requests, time, os, threading, logging, psutil, socket

# -------------------------------------------------------
# Initialization
# -------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

PARSER_URL = os.getenv("PARSER_URL", "http://parser-service:5001")
sniffer_obj, current_iface = None, None
packet_count, last_log_time = 0, time.time()

# -------------------------------------------------------
# Interface auto-detection logic
# -------------------------------------------------------
def detect_best_interface():
    """Detect best available interface for sniffing (K8s or Docker)."""
    runtime = os.getenv("RUNTIME", "docker").lower()

    try:
        # ✅ Kubernetes: use host-mounted /sys/class/net
        if runtime == "k8s" and os.path.exists("/sys/class/net"):
            nets = os.listdir("/sys/class/net")
            for iface in nets:
                if iface.startswith(("en", "eth")) and iface not in ("eth0", "lo"):
                    logging.info(f"🧠 Host-level NIC detected via /sys/class/net: {iface}")
                    return iface

        # ✅ Docker or fallback
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    if iface.startswith(("en", "eth", "ens", "eno")):
                        logging.info(f"🧠 Fallback psutil NIC: {iface}")
                        return iface
        logging.info("⚙️ Defaulting to eth0")
        return "eth0"

    except Exception as e:
        logging.warning(f"⚠️ NIC detection failed, using eth0: {e}")
        return "eth0"

current_iface = detect_best_interface()
logging.info(f"✅ Using interface: {current_iface}")

# -------------------------------------------------------
# Packet sending
# -------------------------------------------------------
def send_packet(pkt, source="LIVE"):
    global packet_count, last_log_time
    packet_count += 1

    src_ip, dst_ip = None, None
    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst

    data = {
        "raw": pkt.summary(),
        "hex": bytes(pkt).hex(),
        "source": source,
        "src_ip": src_ip,
        "dst_ip": dst_ip
    }

    try:
        resp = requests.post(PARSER_URL, json=data, timeout=3)
        if resp.status_code == 200:
            if packet_count % 100 == 0 or (time.time() - last_log_time) > 5:
                logging.info(f"📤 Sent {packet_count} packets (src_ip={src_ip})")
                last_log_time = time.time()
    except Exception as e:
        logging.error(f"❌ Error sending to parser: {e}")

# -------------------------------------------------------
# Sniffer logic
# -------------------------------------------------------
def run_sniffer(mode="LIVE", pcap_file=None, iface_override=None):
    global sniffer_obj, current_iface
    iface = iface_override or current_iface
    current_iface = iface

    try:
        if mode.upper() == "LIVE":
            logging.info(f"🔴 Starting LIVE sniffing on {iface}")
            sniffer_obj = AsyncSniffer(iface=iface,
                                       prn=lambda pkt: send_packet(pkt, source="LIVE"),
                                       store=False)
            sniffer_obj.start()
        else:
            file_to_read = pcap_file or "sample-pcaps/dns.cap"
            logging.info(f"🔵 Reading from PCAP file: {file_to_read}")
            try:
                packets = rdpcap(file_to_read)
            except Exception:
                try:
                    with PcapReader(file_to_read) as pcap_reader:
                        packets = [pkt for pkt in pcap_reader]
                except Exception as e2:
                    logging.error(f"❌ Could not read {file_to_read}: {e2}")
                    packets = []
            for pkt in packets:
                send_packet(pkt, source="PCAP")
            logging.info("🎉 Finished replaying packets.")
    except Exception as e:
        logging.error(f"❌ Sniffer failed: {e}")

# -------------------------------------------------------
# Flask API
# -------------------------------------------------------
@app.route("/start_sniffing", methods=["POST"])
def start_sniffing():
    global sniffer_obj, current_iface

    if sniffer_obj and getattr(sniffer_obj, "running", False):
        logging.warning("⚠️ Sniffer already running, ignoring duplicate start")
        return jsonify({"status": "already_running"}), 200

    mode = request.args.get("mode", "LIVE")
    iface = request.args.get("iface", current_iface)
    pcap_file = request.args.get("file")

    if iface not in psutil.net_if_addrs():
        logging.warning(f"⚠️ Invalid iface={iface}, fallback to {current_iface}")
        iface = current_iface

    logging.info(f"🚀 Starting sniffing on iface={iface} mode={mode}")
    thread = threading.Thread(target=run_sniffer, args=(mode, pcap_file, iface))
    thread.start()
    return jsonify({"status": "sniffing_started", "iface": iface}), 200

@app.route("/stop_sniffing", methods=["POST"])
def stop_sniffing():
    global sniffer_obj
    if sniffer_obj and getattr(sniffer_obj, "running", False):
        sniffer_obj.stop()
        sniffer_obj = None
        logging.info("🛑 Sniffer stopped")
    return jsonify({"status": "stopped"})

@app.route("/interfaces", methods=["GET"])
def list_interfaces():
    hide_prefixes = ("vcan", "tun", "tap", "cni", "wg", "azv")
    filtered = [n for n in psutil.net_if_addrs().keys() if not n.startswith(hide_prefixes)]
    return jsonify({"interfaces": filtered})

@app.route("/status", methods=["GET"])
def status():
    is_running = sniffer_obj and getattr(sniffer_obj, "running", False)
    return jsonify({
        "running": is_running,
        "iface": current_iface,
        "parser_url": PARSER_URL
    })

@app.route("/health", methods=["GET"])
def health():
    return "OK", 200

@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "capture-service running",
        "available_endpoints": ["/health", "/start_sniffing", "/stop_sniffing", "/status", "/interfaces"]
    })

# -------------------------------------------------------
# Main
# -------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("SERVICE_PORT", "5004")))
