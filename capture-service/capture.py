from flask import Flask, request, jsonify
from scapy.all import AsyncSniffer, rdpcap
from scapy.utils import PcapReader
import requests, time, os, threading, logging, psutil, socket, docker

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Parser endpoint inside Docker network
PARSER_URL = "http://127.0.0.1:5001/parse"

sniffer_obj = None   # ✅ AsyncSniffer handle
current_iface = None
last_error = None

# For rate-limited logging
packet_count = 0
last_log_time = time.time()

# ✅ Cache + Docker client for IP → Container name resolution
container_cache = {}
docker_client = docker.from_env()
session_container = None  # track session container once detected
last_src_ip = None
last_container = None


def resolve_container_cached(ip):
    """Resolve container name from IP, using cache + Docker SDK"""
    global container_cache, docker_client, session_container

    if not ip:
        return None

    # return from cache if already known
    if ip in container_cache:
        return container_cache[ip]

    try:
        for c in docker_client.containers.list():
            details = c.attrs
            networks = details.get("NetworkSettings", {}).get("Networks", {})
            for net_name, net_data in networks.items():
                cont_ip = net_data.get("IPAddress")
                if cont_ip == ip:
                    name = c.name
                    container_cache[ip] = name
                    logging.info(f"🔎 Resolved container {name} for IP {ip}")
                    if not session_container:   # set session container if not set
                        session_container = name
                    return name
    except Exception as e:
        logging.warning(f"⚠️ Docker lookup failed for {ip}: {e}")

    return None


def send_packet(pkt, source="LIVE"):
    """Send packet data to parser service with rate-limited logging"""
    global packet_count, last_log_time, last_src_ip, last_container, session_container
    packet_count += 1

    src_ip = None
    container_name = None

    if pkt.haslayer("IP"):   # only if IP packet
        src_ip = pkt["IP"].src
        logging.debug(f"🕵️ Packet src_ip={src_ip}")
        container_name = resolve_container_cached(src_ip)

        # ✅ fallback: check destination IP too
        if not container_name and pkt["IP"].dst:
            container_name = resolve_container_cached(pkt["IP"].dst)

    # If container not detected for this packet, but we already have one for session → reuse
    if not container_name and session_container:
        container_name = session_container

    # Update globals for /status endpoint
    last_src_ip = src_ip
    last_container = container_name

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
            # ✅ log every 100 packets OR every 5s
            if packet_count % 100 == 0 or (time.time() - last_log_time) > 5:
                logging.info(f"📤 Sent {packet_count} packets (latest src_ip={src_ip}, container={container_name})")
                last_log_time = time.time()
    except Exception as e:
        logging.error(f"❌ Error sending to parser: {e}")


def get_default_iface():
    """Detect active default network interface reliably."""
    iface = os.getenv("IFACE")
    if iface:
        logging.info(f"🔧 Using IFACE from env: {iface}")
        return iface

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        available = psutil.net_if_addrs()
        logging.info(f"🌐 Available interfaces: {list(available.keys())}")
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.address == local_ip:
                    logging.info(f"✅ Default route resolved: {iface} ({local_ip})")
                    return iface
    except Exception as e:
        logging.warning(f"⚠️ Could not auto-detect default interface: {e}")
    finally:
        s.close()

    available = list(psutil.net_if_addrs().keys())
    for cand in available:
        if cand != "lo":
            logging.info(f"🌐 Fallback: using {cand}")
            return cand
    logging.warning("⚠️ No external interface found, using loopback 'lo'")
    return "lo"


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


@app.route("/start_sniffing", methods=["POST"])
def start_sniffing():
    global last_error, session_container, sniffer_obj
    last_error = None
    session_container = None  # reset container session when new sniffing starts

    if sniffer_obj and sniffer_obj.running:
        return jsonify({"status": "already_running"}), 400

    mode = request.args.get("mode", "LIVE")
    pcap_file = request.args.get("file")
    iface = request.args.get("iface")

    # validate iface if provided
    if iface:
        available = list(psutil.net_if_addrs().keys())
        if iface not in available:
            logging.error(f"❌ Requested interface '{iface}' not found. Available: {available}")
            last_error = f"Interface '{iface}' not found"
            return jsonify({
                "error": last_error,
                "available": available
            }), 400

    try:
        thread = threading.Thread(target=run_sniffer, args=(mode, pcap_file, iface))
        thread.start()
        return jsonify({
            "status": f"sniffing_started_{mode}",
            "pcap": pcap_file,
            "iface": iface or current_iface
        })
    except Exception as e:
        last_error = str(e)
        logging.error(f"❌ Failed to start sniffer: {e}")
        return jsonify({"error": last_error}), 500


@app.route("/stop_sniffing", methods=["POST"])
def stop_sniffing():
    global sniffer_obj
    if sniffer_obj and sniffer_obj.running:
        sniffer_obj.stop()
        sniffer_obj = None
        logging.info("🛑 Sniffer stopped successfully.")
    else:
        logging.info("ℹ️ No sniffer running.")
    return jsonify({"status": "sniffing_stopped"})


@app.route("/interfaces", methods=["GET"])
def list_interfaces():
    """List host interfaces and map veth/bridge to container/network names.
       Return as objects {name, label} so UI can show pretty label but use raw name."""
    names = list(psutil.net_if_addrs().keys())
    hide_prefixes = ("vcan", "tun", "tap", "cni", "wg")

    filtered = [n for n in names if not n.startswith(hide_prefixes)]

    iface_labels = {}
    try:
        # Map container IPs/MACs to host interfaces
        for c in docker_client.containers.list():
            details = c.attrs
            networks = details.get("NetworkSettings", {}).get("Networks", {})
            for net_name, net_data in networks.items():
                cont_ip = net_data.get("IPAddress")
                cont_mac = net_data.get("MacAddress")
                cont_name = c.name
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.address == cont_ip or addr.address == cont_mac:
                            iface_labels[iface] = cont_name
        # Label bridges by network ID
        for net in docker_client.networks.list():
            bridge_name = f"br-{net.id[:12]}"
            iface_labels[bridge_name] = f"{net.name} (bridge)"
    except Exception as e:
        logging.warning(f"⚠️ Failed to map interfaces: {e}")

    curated = ["eth0", "ens3", "ens5", "enp39s0", "eno1", "docker0", "lo"]
    merged = sorted(dict.fromkeys(curated + filtered))

    final = []
    for iface in merged:
        label = iface_labels.get(iface, "")
        pretty = f"{iface} ({label})" if label else iface
        final.append({"name": iface, "label": pretty})

    return jsonify({"interfaces": final})


@app.route("/status", methods=["GET"])
def status():
    """Return sniffing status + interface + last seen src_ip/container"""
    global last_error, last_src_ip, last_container, sniffer_obj
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

    if MODE:  # manual sniffing
        run_sniffer(MODE, PCAP_FILE)
    else:     # API mode
        app.run(host="0.0.0.0", port=5004)
