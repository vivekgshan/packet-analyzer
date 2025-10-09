from flask import Flask, request, jsonify
from scapy.all import AsyncSniffer, rdpcap, get_if_list
from scapy.utils import PcapReader
import requests, time, os, threading, logging, psutil, socket

# -------------------- Setup --------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Runtime detection
RUNTIME = os.getenv("RUNTIME", "k8s").lower()
USE_DOCKER = RUNTIME == "compose"

PARSER_URL = os.getenv("PARSER_URL", "http://127.0.0.1:5001/parse")

sniffer_obj = None
current_iface = None
last_error = None
packet_count = 0
last_log_time = time.time()

# Docker client init (only when running in Compose)
docker_client, container_cache, session_container = None, {}, None
if USE_DOCKER:
    try:
        import docker
        docker_client = docker.from_env()
        logging.info("✅ Docker client initialized (Compose mode)")
    except Exception as e:
        logging.warning(f"⚠️ Could not init Docker client: {e}")
        docker_client = None


# -------------------- Interface detection --------------------
def detect_iface():
    """Detect best available interface for Docker or K8s."""
    # explicit override
    env_iface = os.getenv("IFACE")
    if env_iface and env_iface in psutil.net_if_addrs():
        return env_iface

    # derive via routing trick
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        for iface, addrs in psutil.net_if_addrs().items():
            if any(addr.address == local_ip for addr in addrs):
                return iface
    except Exception:
        pass

    # host mount detection for AKS
    try:
        host_ifaces = [i for i in get_if_list() if i.startswith(("enp", "ens", "eth"))]
        if host_ifaces:
            return host_ifaces[0]
    except Exception:
        pass

    return "eth0"  # fallback


# -------------------- Container resolver (Compose only) --------------------
def resolve_container_cached(ip):
    """Resolve container name from IP (only in Docker Compose)."""
    global container_cache, docker_client, session_container
    if not ip or not USE_DOCKER or not docker_client:
        return None
    if ip in container_cache:
        return container_cache[ip]
    try:
        for c in docker_client.containers.list():
            for _, net_data in c.attrs.get("NetworkSettings", {}).get("Networks", {}).items():
                if net_data.get("IPAddress") == ip:
                    container_cache[ip] = c.name
                    if not session_container:
                        session_container = c.name
                    logging.info(f"🔎 Resolved container {c.name} for IP {ip}")
                    return c.name
    except Exception as e:
        logging.warning(f"⚠️ Docker lookup failed for {ip}: {e}")
    return None


# -------------------- Packet forwarder --------------------
def send_packet(pkt, source="LIVE"):
    """Send packet summary + hex to parser-service."""
    global packet_count, last_log_time
    src_ip, container_name = None, None

    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        container_name = resolve_container_cached(src_ip) or resolve_container_cached(pkt["IP"].dst)

    data = {
        "raw": pkt.summary(),
        "hex": bytes(pkt).hex(),
        "source": source,
        "src_ip": src_ip,
        "container": container_name,
    }

    try:
        r = requests.post(PARSER_URL, json=data, timeout=3)
        if r.status_code == 200:
            packet_count += 1
            if packet_count % 100 == 0 or (time.time() - last_log_time) > 5:
                logging.info(f"📤 Sent {packet_count} packets (src={src_ip}, cont={container_name})")
                last_log_time = time.time()
    except Exception as e:
        logging.error(f"❌ Error sending to parser: {e}")


# -------------------- Sniffer runner --------------------
def run_sniffer(mode="LIVE", pcap_file=None, iface_override=None):
    """Start AsyncSniffer or replay PCAP file."""
    global sniffer_obj, current_iface, last_error, packet_count
    packet_count = 0
    iface = iface_override or detect_iface()
    current_iface = iface

    try:
        if mode.upper() == "LIVE":
            logging.info(f"🔴 Starting LIVE sniffing on {iface}")
            sniffer_obj = AsyncSniffer(iface=iface, prn=lambda p: send_packet(p, "LIVE"), store=False)
            sniffer_obj.start()
        else:
            file_to_read = pcap_file or "sample-pcaps/dns.cap"
            logging.info(f"🔵 Replaying PCAP: {file_to_read}")
            try:
                packets = rdpcap(file_to_read)
            except Exception:
                with PcapReader(file_to_read) as pr:
                    packets = [p for p in pr]
            for pkt in packets:
                send_packet(pkt, "PCAP")
            logging.info(f"✅ Finished sending {len(packets)} packets from PCAP.")
    except Exception as e:
        last_error = str(e)
        logging.error(f"❌ Sniffer start failed: {e}")


# -------------------- REST API --------------------
@app.route("/start_sniffing", methods=["POST"])
def start_sniffing():
    global sniffer_obj
    if sniffer_obj and getattr(sniffer_obj, "running", False):
        return jsonify({"status": "already_running"}), 400
    mode = request.args.get("mode", "LIVE")
    pcap_file = request.args.get("file")
    iface = request.args.get("iface")
    threading.Thread(target=run_sniffer, args=(mode, pcap_file, iface)).start()
    return jsonify({"status": "sniffing_started", "iface": iface or current_iface})


@app.route("/stop_sniffing", methods=["POST"])
def stop_sniffing():
    global sniffer_obj
    if sniffer_obj and getattr(sniffer_obj, "running", False):
        sniffer_obj.stop()
        sniffer_obj = None
        logging.info("🛑 Sniffer stopped")
    return jsonify({"status": "sniffing_stopped"})


@app.route("/interfaces", methods=["GET"])
def list_interfaces():
    """Return visible interfaces for UI dropdown."""
    names = list(psutil.net_if_addrs().keys())
    hide_prefixes = ("vcan", "tun", "tap", "cni", "wg")
    filtered = [n for n in names if not n.startswith(hide_prefixes)]

    iface_labels = {}
    if USE_DOCKER and docker_client:
        try:
            for c in docker_client.containers.list():
                for _, net_data in c.attrs.get("NetworkSettings", {}).get("Networks", {}).items():
                    cont_ip = net_data.get("IPAddress")
                    cont_mac = net_data.get("MacAddress")
                    cont_name = c.name
                    for iface, addrs in psutil.net_if_addrs().items():
                        for addr in addrs:
                            if addr.address in (cont_ip, cont_mac):
                                iface_labels[iface] = cont_name
        except Exception as e:
            logging.warning(f"⚠️ Failed to map interfaces: {e}")

    curated = ["eth0", "ens3", "ens5", "enp39s0", "eno1", "docker0", "lo"]
    merged = sorted(dict.fromkeys(curated + filtered))
    final = [{"name": i, "label": f"{i} ({iface_labels.get(i,'')})".strip()} for i in merged]
    return jsonify({"interfaces": final})


@app.route("/status", methods=["GET"])
def status():
    running = bool(sniffer_obj and getattr(sniffer_obj, "running", False))
    return jsonify({
        "running": running,
        "iface": current_iface,
        "error": last_error,
        "packet_count": packet_count
    })


@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "capture-service running",
        "parser_url": PARSER_URL,
        "runtime": RUNTIME,
        "interfaces_hint": get_if_list()
    })


# -------------------- Entrypoint --------------------
if __name__ == "__main__":
    MODE = os.getenv("MODE")
    PCAP_FILE = os.getenv("PCAP_FILE")
    if MODE:
        run_sniffer(MODE, PCAP_FILE)
    else:
        app.run(host="0.0.0.0", port=int(os.getenv("SERVICE_PORT", "5004")))
