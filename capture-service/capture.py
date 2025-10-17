from flask import Flask, request, jsonify
from scapy.all import AsyncSniffer, rdpcap
import requests, time, os, threading, logging, psutil, socket, struct

# -------------------------------------------------------
# Runtime detection
# -------------------------------------------------------
RUNTIME = os.getenv("RUNTIME", "").lower()
USE_K8S = "k8s" in RUNTIME
USE_DOCKER = not USE_K8S

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -------------------------------------------------------
# Global vars
# -------------------------------------------------------
PARSER_URL = os.getenv("PARSER_URL", "http://parser-service:5001")
sniffer_obj, current_iface = None, None
packet_count, last_log_time = 0, time.time()

# -------------------------------------------------------
# Interface detection
# -------------------------------------------------------
def detect_best_interface():
    """Detects best interface to sniff packets."""
    try:
        nets = os.listdir("/sys/class/net")
        for iface in nets:
            if iface.startswith(("en", "eth")) and iface not in ("eth0", "lo"):
                logging.info(f"🧠 Host-level NIC detected via /sys/class/net: {iface}")
                return iface
        # fallback
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return iface
        return "eth0"
    except Exception as e:
        logging.warning(f"⚠️ NIC detection failed, using eth0: {e}")
        return "eth0"

# -------------------------------------------------------
# Packet sending
# -------------------------------------------------------
def send_packet(pkt, source="LIVE"):
    global packet_count, last_log_time
    packet_count += 1
    src_ip, dst_ip = None, None
    if hasattr(pkt, "haslayer") and pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst

    data = {
        "raw": pkt.summary() if hasattr(pkt, "summary") else str(pkt),
        "hex": bytes(pkt).hex() if hasattr(pkt, "__bytes__") else "",
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
# Raw socket fallback for Kubernetes
# -------------------------------------------------------
def raw_sniff_fallback(iface):
    """Raw socket sniffing — works even when Scapy can't attach in K8s."""
    logging.info(f"⚡ Using raw socket fallback on host NIC: {iface}")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((iface, 0))
        while True:
            raw_data, addr = sock.recvfrom(65535)
            eth_proto = struct.unpack('!6s6sH', raw_data[:14])[2]
            send_packet(raw_data[:60], source="RAW")
    except Exception as e:
        logging.error(f"❌ Raw sniff failed on {iface}: {e}")

# -------------------------------------------------------
# Sniffer
# -------------------------------------------------------
def run_sniffer(mode="LIVE", pcap_file=None, iface_override=None):
    global sniffer_obj, current_iface

    host_iface = os.getenv("HOST_IFACE", "enp39s0")
    pod_iface = os.getenv("POD_IFACE", "eth0")
    iface_list = [host_iface, pod_iface]

    current_iface = ",".join(iface_list)
    logging.info(f"🧠 K8s runtime detected — sniffing on host={host_iface}, pod={pod_iface}")

    if mode.upper() == "LIVE":
        try:
            # Multi-interface sniff
            sniffer_obj = AsyncSniffer(
                iface=iface_list,
                prn=lambda pkt: send_packet(pkt, source="LIVE"),
                store=False
            )
            sniffer_obj.start()
            logging.info(f"⚡ Sniffing started on {iface_list}")
        except Exception as e:
            logging.error(f"❌ Error starting multi-interface sniffer: {e}")
    else:
        ...

# -------------------------------------------------------
# Flask endpoints
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

    valid_ifaces = psutil.net_if_addrs().keys()
    if iface not in valid_ifaces:
        logging.warning(f"⚠️ Interface {iface} not found, defaulting to {current_iface}")
        iface = current_iface

    logging.info(f"🚀 Starting sniffing on iface={iface} mode={mode}")
    try:
        thread = threading.Thread(target=run_sniffer, args=(mode, pcap_file, iface))
        thread.start()
        return jsonify({"status": "sniffing_started", "iface": iface}), 200
    except Exception as e:
        logging.error(f"❌ Error starting sniffer: {e}")
        return jsonify({"error": str(e)}), 500

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
    names = list(psutil.net_if_addrs().keys())
    hide_prefixes = ("vcan", "tun", "tap", "cni", "wg", "azv")
    filtered = [n for n in names if not n.startswith(hide_prefixes)]
    return jsonify({"interfaces": filtered})

@app.route("/status", methods=["GET"])
def status():
    is_running = sniffer_obj and getattr(sniffer_obj, "running", False)
    return jsonify({"running": is_running, "iface": current_iface, "parser_url": PARSER_URL})

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
    mode = os.getenv("MODE", "LIVE")
    pcap = os.getenv("PCAP_FILE")
    run_sniffer(mode, pcap)
    app.run(host="0.0.0.0", port=int(os.getenv("SERVICE_PORT", "5004")))
