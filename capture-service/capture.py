from flask import Flask, request, jsonify
from scapy.all import sniff, rdpcap, get_if_list
from scapy.utils import PcapReader
import requests, time, os, threading, logging, psutil,socket

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Parser endpoint inside Docker network
# PARSER_URL = "http://parser-service:5001/parse"
PARSER_URL = "http://127.0.0.1:5001/parse"

sniff_thread = None
stop_flag = False
current_iface = None

# For rate-limited logging
packet_count = 0
last_log_time = time.time()


def send_packet(pkt, source="LIVE"):
    """Send packet data to parser service with rate-limited logging"""
    global packet_count, last_log_time
    packet_count += 1
    data = {
        "raw": pkt.summary(),
        "hex": bytes(pkt).hex(),
        "source": source
    }
    try:
        resp = requests.post(PARSER_URL, json=data, timeout=3)
        if resp.status_code == 200:
            # ✅ log every 100 packets OR every 5s
            if packet_count % 100 == 0 or (time.time() - last_log_time) > 5:
                logging.info(f"📤 Sent {packet_count} packets so far (latest={data['raw'][:50]})")
                last_log_time = time.time()
    except Exception as e:
        logging.error(f"❌ Error sending to parser: {e}")



def get_default_iface():
    """Auto-detect the default network interface for outbound traffic."""

    try:
        # 🔹 Create a temporary UDP socket
        # (UDP is used here because it's connectionless and very lightweight)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # 🔹 "Connect" to 8.8.8.8:80 (Google DNS)
        # 👉 Important: no packets are actually sent!
        # This only asks the kernel:
        #   "If I wanted to reach 8.8.8.8:80, which local IP/interface would I use?"
        s.connect(("8.8.8.8", 80))

        # 🔹 Get the local IP address the OS chose
        local_ip = s.getsockname()[0]

        # 🔹 Find the network interface name that owns this local IP
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.address == local_ip:
                    logging.info(f"✅ Default route resolved: {iface} ({local_ip})")
                    return iface

    except Exception as e:
        logging.warning(f"⚠️ Could not auto-detect default interface: {e}")

    finally:
        s.close()

    # 🔹 Fallbacks in case auto-detect fails
    available = list(psutil.net_if_addrs().keys())
    logging.info(f"🌐 Available interfaces: {available}")

    # Step 1: Pick the first non-loopback interface
    # 👉 Loopback ("lo") is the internal-only interface.
    #    We avoid it if there are real network interfaces available.
    for cand in available:
        if cand != "lo":  # skip loopback if possible
            logging.info(f"🌐 Fallback: using {cand}")
            return cand

    # Step 2: Absolute last resort
    # 👉 If only "lo" exists (for example in very isolated environments
    #    or inside some containers), then we must use it.
    logging.warning("⚠️ No external interface found, using loopback 'lo'")
    return "lo"



def run_sniffer(mode="LIVE", pcap_file=None):
    """Run live or PCAP sniffing"""
    global stop_flag, packet_count, last_log_time, current_iface
    stop_flag = False
    packet_count = 0
    last_log_time = time.time()
    time.sleep(2)

    if mode.upper() == "LIVE":
        iface = get_default_iface()
        current_iface = iface   # ✅ save detected iface
        logging.info(f"🔴 Started sniffing on {iface}...")
        sniff(
            iface=iface,
            prn=lambda pkt: send_packet(pkt, source="LIVE"),
            store=False,
            stop_filter=lambda pkt: stop_flag      # ✅ stop sniffing gracefully
        )
        logging.info("🛑 Sniffing stopped (LIVE mode).")

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

        logging.info(f"✅ Loaded {len(packets)} packets from {file_to_read}")
        for pkt in packets:
            if stop_flag:
                break
            send_packet(pkt, source="PCAP")
        logging.info("🎉 Finished sending all packets from PCAP.")


@app.route("/start_sniffing", methods=["POST"])
def start_sniffing():
    global sniff_thread, stop_flag, current_iface
    if sniff_thread and sniff_thread.is_alive():
        return jsonify({"status": "already_running"}), 400

    mode = request.args.get("mode", "LIVE")
    pcap_file = request.args.get("file")

     # Detect iface before starting thread
    if mode.upper() == "LIVE":
        current_iface = get_default_iface()
    else:
        current_iface = None
        
    sniff_thread = threading.Thread(target=run_sniffer, args=(mode, pcap_file))
    sniff_thread.start()

    # ✅ return the same iface actually being used
    return jsonify({"status": f"sniffing_started_{mode}", "pcap": pcap_file, "iface": current_iface})


@app.route("/stop_sniffing", methods=["POST"])
def stop_sniffing():
    global stop_flag
    stop_flag = True
    logging.info("🛑 Stop request received — stopping sniffer...")
    return jsonify({"status": "sniffing_stopped"})


@app.route("/status", methods=["GET"])
def status():
    """✅ New endpoint to return sniffing status + interface"""
    is_running = sniff_thread and sniff_thread.is_alive()
    return jsonify({
        "running": is_running,
        "iface": current_iface if is_running else None
    })


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "capture-service running",
        "available_endpoints": ["/health", "/start_sniffing", "/stop_sniffing", "/status"]
    })


@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


if __name__ == "__main__":
    MODE = os.getenv("MODE")
    PCAP_FILE = os.getenv("PCAP_FILE")

    if MODE:  # manual sniffing
        run_sniffer(MODE, PCAP_FILE)
    else:     # API mode
        app.run(host="0.0.0.0", port=5004)
