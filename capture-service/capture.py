from flask import Flask, request, jsonify
from scapy.all import AsyncSniffer, rdpcap
from scapy.utils import PcapReader
import requests, time, os, threading, logging, psutil, socket

# Detect runtime
USE_DOCKER = os.getenv("RUNTIME", "k8s").lower() == "compose"
if USE_DOCKER:
    import docker

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Parser endpoint
PARSER_URL = os.getenv("PARSER_URL", "http://127.0.0.1:5001/parse")

sniffer_obj = None
current_iface = None
last_error = None

packet_count = 0
last_log_time = time.time()

container_cache = {}
docker_client = None
if USE_DOCKER:
    try:
        docker_client = docker.from_env()
        logging.info("✅ Docker client initialized (Compose mode)")
    except Exception as e:
        logging.warning(f"⚠️ Could not init Docker client: {e}")
        docker_client = None

session_container = None
last_src_ip = None
last_container = None


def resolve_container_cached(ip):
    """Resolve container name by IP (Docker in Compose, None in K8s)."""
    global container_cache, docker_client, session_container

    if not ip:
        return None

    if ip in container_cache:
        return container_cache[ip]

    if USE_DOCKER and docker_client:
        try:
            for c in docker_client.containers.list():
                details = c.attrs
                networks = details.get("NetworkSettings", {}).get("Networks", {})
                for _, net_data in networks.items():
                    if net_data.get("IPAddress") == ip:
                        name = c.name
                        container_cache[ip] = name
                        if not session_container:
                            session_container = name
                        logging.info(f"🔎 Resolved container {name} for IP {ip}")
                        return name
        except Exception as e:
            logging.warning(f"⚠️ Docker lookup failed for {ip}: {e}")

    return None


def send_packet(pkt, source="LIVE"):
    """Send packet data to parser service"""
    global packet_count, last_log_time, last_src_ip, last_container, session_container
    packet_count += 1

    src_ip, container_name = None, None
    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        container_name = resolve_container_cached(src_ip)
        if not container_name and pkt["IP"].dst:
            container_name = resolve_container_cached(pkt["IP"].dst)

    if not container_name and session_container:
        container_name = session_container

    last_src_ip, last_container = src_ip, container_name

    data = {
        "raw": pkt.summary(),
        "hex": bytes(pkt).hex(),
        "source": source,
        "src_ip": src_ip,
        "container": container_name
    }

    try:
        resp = requests.post(PARSER_URL, json=data, timeout=3)
        if resp.status_code == 200:
            if packet_count % 100 == 0 or (time.time() - last_log_time) > 5:
                logging.info(f"📤 Sent {packet_count} packets (src_ip={src_ip}, container={container_name})")
                last_log_time = time.time()
    except Exception as e:
        logging.error(f"❌ Error sending to parser: {e}")


def get_default_iface():
    """Detect default interface (works in both Docker & K8s)."""
    iface = os.getenv("IFACE")
    if iface:
        return iface

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        for iface, addrs in psutil.net_if_addrs().items():
            if any(addr.address == local_ip for addr in addrs):
                return iface
    except Exception:
        pass
    finally:
        s.close()

    return "eth0"


def run_sniffer(mode="LIVE", pcap_file=None, iface_override=None):
    """Start AsyncSniffer or replay from PCAP"""
    global packet_count, last_log_time, current_iface, sniffer_obj
    packet_count = 0
    last_log_time = time.time()
    time.sleep(2)

    if mode.upper() == "LIVE":
        iface = iface_override or get_default_iface()
        current_iface = iface
        logging.info(f"🔴 Started sniffing on {iface}...")

        sniffer_obj = AsyncSniffer(
            iface=iface,
            prn=lambda pkt: send_packet(pkt, source="LIVE"),
            store=False
        )
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

        logging.info(f"✅ Loaded {len(packets)} packets from {file_to_read}")
        for pkt in packets:
            send_packet(pkt, source="PCAP")
        logging.info("🎉 Finished sending all packets from PCAP.")


# ---------------- API Endpoints ----------------
@app.route("/start_sniffing", methods=["POST"])
def start_sniffing():
    global last_error, session_container, sniffer_obj
    last_error = None
    session_container = None

    if sniffer_obj and sniffer_obj.running:
        return jsonify({"status": "already_running"}), 400

    mode = request.args.get("mode", "LIVE")
    pcap_file = request.args.get("file")
    iface = request.args.get("iface")

    if iface and iface not in psutil.net_if_addrs().keys():
        last_error = f"Interface '{iface}' not found"
        return jsonify({"error": last_error}), 400

    try:
        thread = threading.Thread(target=run_sniffer, args=(mode, pcap_file, iface))
        thread.start()
        return jsonify({"status": f"sniffing_started_{mode}", "pcap": pcap_file, "iface": iface or current_iface})
    except Exception as e:
        last_error = str(e)
        return jsonify({"error": last_error}), 500


@app.route("/stop_sniffing", methods=["POST"])
def stop_sniffing():
    global sniffer_obj
    if sniffer_obj and sniffer_obj.running:
        sniffer_obj.stop()
        sniffer_obj = None
    return jsonify({"status": "sniffing_stopped"})


@app.route("/interfaces", methods=["GET"])
def list_interfaces():
    names = list(psutil.net_if_addrs().keys())
    hide_prefixes = ("vcan", "tun", "tap", "cni", "wg")
    filtered = [n for n in names if not n.startswith(hide_prefixes)]

    iface_labels = {}
    if USE_DOCKER and docker_client:
        try:
            for c in docker_client.containers.list():
                details = c.attrs
                networks = details.get("NetworkSettings", {}).get("Networks", {})
                for _, net_data in networks.items():
                    cont_ip = net_data.get("IPAddress")
                    cont_mac = net_data.get("MacAddress")
                    cont_name = c.name
                    for iface, addrs in psutil.net_if_addrs().items():
                        for addr in addrs:
                            if addr.address == cont_ip or addr.address == cont_mac:
                                iface_labels[iface] = cont_name
        except Exception as e:
            logging.warning(f"⚠️ Failed to map interfaces: {e}")

    curated = ["eth0", "ens3", "ens5", "enp39s0", "eno1", "docker0", "lo"]
    merged = sorted(dict.fromkeys(curated + filtered))

    final = [{"name": iface, "label": f"{iface} ({iface_labels.get(iface,'')})".strip()} for iface in merged]
    return jsonify({"interfaces": final})


@app.route("/status", methods=["GET"])
def status():
    is_running = sniffer_obj and sniffer_obj.running
    return jsonify({
        "running": is_running,
        "iface": current_iface if is_running else None,
        "error": last_error,
        "last_src_ip": last_src_ip,
        "last_container": last_container
    })


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "capture-service running",
        "available_endpoints": ["/health", "/start_sniffing", "/stop_sniffing", "/status", "/interfaces"]
    })


@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


if __name__ == "__main__":
    MODE = os.getenv("MODE")
    PCAP_FILE = os.getenv("PCAP_FILE")

    if MODE:
        run_sniffer(MODE, PCAP_FILE)
    else:
        app.run(host="0.0.0.0", port=5004)
