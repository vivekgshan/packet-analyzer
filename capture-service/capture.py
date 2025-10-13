from flask import Flask, request, jsonify
from scapy.all import AsyncSniffer, rdpcap
from scapy.utils import PcapReader
import requests, time, os, threading, logging, psutil, socket

# -------------------------------------------------------
# Runtime detection
# -------------------------------------------------------
RUNTIME = os.getenv("RUNTIME", "").lower()
USE_K8S = RUNTIME == "k8s" or os.path.exists("/var/run/secrets/kubernetes.io")
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -------------------------------------------------------
# Globals
# -------------------------------------------------------
PARSER_URL = os.getenv("PARSER_URL", "http://parser-service:5001")
sniffer_obj, current_iface = None, None
packet_count, last_log_time = 0, time.time()

# -------------------------------------------------------
# Interface detection
# -------------------------------------------------------
def detect_best_interface():
    """
    Detects the best interface for packet sniffing.
    - In Docker Compose, this will be eth0.
    - In Kubernetes, it checks mounted host NICs under /sys/class/net.
    """
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
                    if iface.startswith(("en", "eth")):
                        logging.info(f"🧠 Fallback psutil NIC: {iface}")
                        return iface
        logging.info("⚙️ Defaulting to eth0")
        return "eth0"

    except Exception as e:
        logging.warning(f"⚠️ NIC detection failed, defaulting to eth0: {e}")
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
        "raw": pkt.summary() if hasattr(pkt, "summary") else str(pkt)[:80],
        "hex": bytes(pkt).hex() if hasattr(pkt, "__bytes__") else "",
        "source": source,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }

    try:
        resp = requests.post(PARSER_URL, json=data, timeout=3)
        if resp.status_code == 200 and (packet_count % 100 == 0 or (time.time() - last_log_time) > 5):
            logging.info(f"📤 Sent {packet_count} packets (src_ip={src_ip})")
            last_log_time = time.time()
    except Exception as e:
        logging.error(f"❌ Error sending to parser: {e}")

# -------------------------------------------------------
# Fallback raw socket sniffer (for host NICs)
# -------------------------------------------------------
def raw_sniff_fallback(iface):
    """Direct raw socket sniffer for host-level NICs (K8s DaemonSet)"""
    logging.info(f"⚡ Using raw socket fallback on host NIC: {iface}")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.bind((iface, 0))
        while True:
            pkt, addr = s.recvfrom(65535)
            send_packet(type("FakePkt", (), {
                "summary": lambda self=pkt: f"RAW_PACKET len={len(pkt)}",
                "__bytes__": lambda self=pkt: pkt
            })())
    except PermissionError:
        logging.error("❌ Permission denied — ensure NET_ADMIN and privileged=true")
    except Exception as e:
        logging.error(f"❌ Raw sniff failed on {iface}: {e}")

# -------------------------------------------------------
# Sniffer logic
# -------------------------------------------------------
def can_sniff_iface(iface):
    return iface in psutil.net_if_addrs()

def run_sniffer(mode="LIVE", pcap_file=None, iface_override=None):
    global sniffer_obj, current_iface
    iface = iface_override or detect_best_interface()
    current_iface = iface

    if mode.upper() == "LIVE":
        logging.info(f"🔴 Starting LIVE sniffing on {iface}")
        if can_sniff_iface(iface):
            logging.info("✅ Scapy interface found — using AsyncSniffer")
            sniffer_obj = AsyncSniffer(iface=iface, prn=lambda pkt: send_packet(pkt, source="LIVE"), store=False)
            sniffer_obj.start()
        else:
            logging.info("🧠 K8s runtime detected — forcing raw socket sniffing")
            thread = threading.Thread(target=raw_sniff_fallback, args=(iface,))
            thread.daemon = True
            thread.start()
    else:
        file_to_read = pcap_file or "sample-pcaps/dns.cap"
        logging.info(f"🔵 Reading packets from PCAP file: {file_to_read}")
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

    valid_ifaces = psutil.net_if_addrs().keys()
    if iface not in valid_ifaces:
        logging.warning(f"⚠️ Interface {iface} not found, defaulting to {current_iface}")
        iface = current_iface

    logging.info(f"🚀 Starting sniffing on iface={iface} mode={mode}")
    try:
        sniffer_obj = threading.Thread(target=run_sniffer, args=(mode, pcap_file, iface))
        sniffer_obj.daemon = True
        sniffer_obj.start()
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
    hide_prefixes = ("vcan", "tun", "tap", "cni", "wg", "azv")
    names = [n for n in psutil.net_if_addrs().keys() if not n.startswith(hide_prefixes)]
    return jsonify({"interfaces": names})

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
# Main entry
# -------------------------------------------------------
if __name__ == "__main__":
    mode = os.getenv("MODE", "LIVE")
    pcap = os.getenv("PCAP_FILE")
    run_sniffer(mode, pcap)
    app.run(host="0.0.0.0", port=int(os.getenv("SERVICE_PORT", "5004")))
