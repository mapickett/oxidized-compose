from flask import Flask, jsonify, request, Response
import csv
import os
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from OpenSSL import crypto
from prometheus_client import generate_latest, Gauge, Counter, CollectorRegistry, CONTENT_TYPE_LATEST

app = Flask(__name__)

# === CONFIGURATION ===
USERNAME = "oxidized"
PASSWORD = "secret"
INVENTORY_FILE = "router.db"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# === METRICS REGISTRY ===
registry = CollectorRegistry()
device_count_gauge = Gauge("oxidized_inventory_device_count", "Total devices in inventory", registry=registry)
inventory_reload_counter = Counter("oxidized_inventory_reloads_total", "Number of times inventory reloaded", registry=registry)
last_reload_timestamp = Gauge("oxidized_inventory_last_reload_timestamp", "Last time inventory was loaded", registry=registry)

# === CACHE ===
inventory_cache = []

# === AUTH ===
def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    return Response(
        "Authentication required", 401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# === LOAD INVENTORY ===
def load_inventory():
    global inventory_cache
    if not os.path.isfile(INVENTORY_FILE):
        inventory_cache = []
        device_count_gauge.set(0)
        return

    devices = []
    with open(INVENTORY_FILE, newline='') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=':')
        for row in reader:
            device = {
                "name": row.get("name", "").strip(),
                "ip": row.get("ip", "").strip(),
                "model": row.get("model", "").strip()
            }
            for field in ["group", "username", "password"]:
                value = row.get(field)
                if value:
                    device[field] = value.strip()
            devices.append(device)

    inventory_cache = devices
    device_count_gauge.set(len(devices))
    inventory_reload_counter.inc()
    last_reload_timestamp.set_to_current_time()
    print(f"Loaded {len(devices)} devices from inventory.")

# === FILE WATCHER ===
class InventoryFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(INVENTORY_FILE):
            print("Inventory file changed, reloading...")
            load_inventory()

# === CERTIFICATE GENERATION ===
def generate_self_signed_cert(cert_file, key_file):
    print("Generating self-signed SSL certificate...")
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "Local"
    cert.get_subject().L = "Localhost"
    cert.get_subject().O = "Oxidized Inventory API"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    with open(cert_file, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(key_file, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))

# === ROUTES ===

@app.route("/oxidized/inventory", methods=["GET"])
@requires_auth
def get_inventory():
    return jsonify(inventory_cache)

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok"}), 200

@app.route("/metrics", methods=["GET"])
def metrics():
    return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)

# === MAIN ENTRY POINT ===
if __name__ == "__main__":
    # Generate certs if missing
    if not os.path.isfile(CERT_FILE) or not os.path.isfile(KEY_FILE):
        generate_self_signed_cert(CERT_FILE, KEY_FILE)

    # Load inventory once
    load_inventory()

    # Watch file for changes
    observer = Observer()
    observer.schedule(InventoryFileHandler(), path=".", recursive=False)
    observer_thread = threading.Thread(target=observer.start)
    observer_thread.daemon = True
    observer_thread.start()

    print("✅ Oxidized Inventory API is running at https://localhost:5000")
    app.run(host="0.0.0.0", port=5000, ssl_context=(CERT_FILE, KEY_FILE))
