from flask import Flask, request, jsonify
from scapy.all import AsyncSniffer, rdpcap
from scapy.utils import PcapReader
import requests, time, os, threading, logging, psutil, socket

# -------------------------------------------------------
# Runtime detection
# -------------------------------------------------------
RUNTIME = os.getenv("RUNTIME", "").lower()
USE_DOCKER = "compose" in RUNTIME or os.path.exists("/.dockerenv")

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -------------------------------------------------------
# Global vars
# -------------------------------------------------------
PARSER_URL = os.getenv("PARSER_URL", "http://parser-service:5001")
sniffer_obj, current_iface, last_error = None, None, None
packet_count, last_log_time = 0, time.time()

# -------------------------------------------------------
# Interface auto-detection logic
# -------------------------------------------------------
import psutil, socket, os, logging

def get_best_iface():
    """
    Auto-detects the best NIC for packet capture.
    ✅ Works for Docker, Compose, and Kubernetes (DaemonSet with hostNetwork)
    """
    try:
        # 🧩 1. Check mounted host interfaces first
        host_net_path = "/host-net"
        if os.path.exists(host_net_path):
            host_ifaces = [i for i in os.listdir(host_net_path)
                           if not i.startswith(("lo", "veth", "docker", "cni", "azv"))]
            logging.info(f"🌐 Host interfaces from /host-net: {host_ifaces}")
            for iface in host_ifaces:
                if iface.lower().startswith(("en", "ens", "eno")):
                    logging.info(f"🧠 Selected host NIC: {iface}")
                    return iface

        # 🧩 2. Otherwise, inspect in-container NICs
        ifaces = list(psutil.net_if_addrs().keys())
        logging.info(f"🔍 Container-visible interfaces: {ifaces}")

        for iface in ifaces:
            addrs = psutil.net_if_addrs().get(iface, [])
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    logging.info(f"🧠 Selected container NIC: {iface} ({addr.address})")
                    return iface

        logging.warning("⚙️ No suitable NIC found; using eth0 as fallback")
    except Exception as e:
        logging.warning(f"⚠️ Interface auto-detect failed: {e}")

    return "eth0"


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
# Sniffer
# -------------------------------------------------------
def run_sniffer(mode="LIVE", pcap_file=None, iface_override=None):
    global sniffer_obj, current_iface
    iface = iface_override or get_best_iface()
    current_iface = iface

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

# -------------------------------------------------------
# Flask API
# -------------------------------------------------------
@app.route("/start_sniffing", methods=["POST"])
def start_sniffing():
    global sniffer_obj
    if sniffer_obj and sniffer_obj.running:
        return jsonify({"status": "already_running"}), 400

    mode = request.args.get("mode", "LIVE")
    iface = request.args.get("iface")
    pcap_file = request.args.get("file")

    try:
        thread = threading.Thread(target=run_sniffer, args=(mode, pcap_file, iface))
        thread.start()
        return jsonify({"status": "sniffing_started", "iface": iface or current_iface})
    except Exception as e:
        logging.error(f"❌ Error starting sniffer: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/stop_sniffing", methods=["POST"])
def stop_sniffing():
    global sniffer_obj
    if sniffer_obj and sniffer_obj.running:
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
    is_running = sniffer_obj and sniffer_obj.running
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
    mode = os.getenv("MODE", "LIVE")
    pcap = os.getenv("PCAP_FILE")
    run_sniffer(mode, pcap)
    app.run(host="0.0.0.0", port=int(os.getenv("SERVICE_PORT", "5004")))
