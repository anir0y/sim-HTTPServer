import logging
import os
import socket
from flask import Flask, request, jsonify
from scapy.all import sniff, wrpcap  # For packet capturing
import psutil  # To detect network interfaces

app = Flask(__name__)

# Get absolute path for the log file
log_file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'requests.log')
pcap_file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'captured_traffic.pcap')

# Print the log file path for debugging
print(f"Log file path: {log_file_path}")
print(f"PCAP file path: {pcap_file_path}")

# Check if the directory is writable
if os.access(os.path.dirname(log_file_path), os.W_OK):
    print("Directory is writable")
else:
    print("Directory is NOT writable")

# Set up logging with a backup handler to the console in case of issues
try:
    logging.basicConfig(filename=log_file_path, level=logging.INFO,
                        format='%(asctime)s - %(message)s')
    logging.info("Logging initialized.")
    print("Logging initialized successfully.")
except Exception as e:
    print(f"Failed to initialize logging: {e}")


# Function to get the private IP
def get_private_ip():
    try:
        hostname = socket.gethostname()
        private_ip = socket.gethostbyname(hostname)
        return private_ip
    except Exception as e:
        logging.error(f"Error retrieving private IP: {e}")
        return "Unknown"


# Function to detect the loopback interface dynamically
def get_loopback_interface():
    """
    Detects the loopback interface dynamically.
    :return: Name of the loopback interface (e.g., 'lo', 'lo0') or None if not found.
    """
    try:
        addrs = psutil.net_if_addrs()
        for interface, addresses in addrs.items():
            for addr in addresses:
                if addr.address == "127.0.0.1":  # IPv4 loopback address
                    print(f"Detected loopback interface: {interface}")
                    return interface
        print("No loopback interface detected!")
        return None
    except Exception as e:
        print(f"Error detecting loopback interface: {e}")
        return None


# Packet capture function
def start_packet_capture(interface=None, count=100):
    """
    Captures network packets and saves them to a .pcap file.
    :param interface: Network interface to capture packets from (default: None for all interfaces)
    :param count: Number of packets to capture
    """
    try:
        if interface:
            print(f"Starting packet capture on interface {interface}...")
            packets = sniff(iface=interface, count=count)
        else:
            print("No valid interface provided for packet capture.")
            return
        wrpcap(pcap_file_path, packets)
        print(f"Captured {len(packets)} packets and saved to {pcap_file_path}")
        logging.info(f"Captured {len(packets)} packets and saved to {pcap_file_path}")
    except Exception as e:
        print(f"Error during packet capture: {e}")
        logging.error(f"Error during packet capture: {e}")


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    log_data = []
    log_data.append(f"Received {request.method} request for /{path}")
    log_data.append("Headers:")
    for header, value in request.headers.items():
        log_data.append(f"{header}: {value}")
    log_data.append("Body:")
    log_data.append(request.get_data(as_text=True))

    # Log to file
    logging.info("\n".join(log_data))
    # Optionally, print the log data to console as well
    print("\n".join(log_data))
    print("=={EOR}==")
    return "Server:OK\r\n"


@app.route('/simulate-login', methods=['POST'])
def simulate_login_route():
    """
    Handles POST requests to simulate an HTTP login.
    Expects JSON payload with 'url', 'username', and 'password'.
    """
    try:
        data = request.get_json()
        url = data.get("url")
        username = data.get("username")
        password = data.get("password")

        if not all([url, username, password]):
            return jsonify({"error": "Missing required fields"}), 400

        # Log the login details
        logging.info(f"Simulating login: URL={url}, Username={username}")
        print(f"Simulating login: URL={url}, Username={username}")

        return jsonify({"message": "Login simulation triggered!"}), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


if __name__ == "__main__":
    try:
        private_ip = get_private_ip()

        # Log IPs as requested
        logging.info(f"[+] Private IP: {private_ip}")
        print(f"[+] Private IP: {private_ip}")

        # Detect the loopback interface
        loopback_interface = get_loopback_interface()

        # Start packet capture in a separate thread
        import threading
        if loopback_interface:
            capture_thread = threading.Thread(target=start_packet_capture, args=(loopback_interface, 100))
            capture_thread.daemon = True
            capture_thread.start()
        else:
            print("Packet capture will not start due to missing loopback interface.")

        # Run Flask app
        app.run(host='0.0.0.0', port=80)
    except Exception as e:
        logging.error(f"Error starting Flask app: {e}")
        print(f"Error starting Flask app: {e}")