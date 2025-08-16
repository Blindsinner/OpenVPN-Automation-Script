import os
import time
import requests
import zipfile
import subprocess
import glob
import shutil
import logging
from typing import List, Optional

# Suppress HTTPS warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# VPN Credentials
VPN_USERNAME = "vpnbook"
VPN_PASSWORD = "cf32e5w"

# Directories and Constants
VPN_CONFIG_DIR = "/tmp/vpn_configs"
OVPN_EXTENSION = "*.ovpn"

# Direct links to the .zip files
ZIP_LINKS = [
    "https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-ca149.zip",
    "https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-de20.zip",
    "https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-fr200.zip",
    "https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-pl134.zip",
    "https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-uk205.zip"
]

def cleanup():
    """Remove old VPN files."""
    if os.path.exists(VPN_CONFIG_DIR):
        for item in os.listdir(VPN_CONFIG_DIR):
            item_path = os.path.join(VPN_CONFIG_DIR, item)
            try:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)  # Delete non-empty folders
                else:
                    os.remove(item_path)  # Delete files
            except Exception as e:
                logging.error(f"Error deleting {item_path}: {e}")
    os.makedirs(VPN_CONFIG_DIR, exist_ok=True)
    logging.info("Old VPN files removed.")

def download_vpn_configs() -> List[str]:
    """Download latest VPNBook configuration files."""
    downloaded_files = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
    for zip_link in ZIP_LINKS:
        zip_filename = os.path.join(VPN_CONFIG_DIR, os.path.basename(zip_link))
        try:
            logging.info(f"Downloading: {zip_link}")
            response = requests.get(zip_link, headers=headers, stream=True, verify=False)
            response.raise_for_status()
            with open(zip_filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
            downloaded_files.append(zip_filename)
            logging.info(f"Downloaded: {os.path.basename(zip_filename)}")
        except Exception as e:
            logging.error(f"Error downloading {zip_link}: {e}")
    return downloaded_files

def extract_and_modify() -> List[str]:
    """Extract and modify .ovpn files to bypass VPN for real IP and specific ports."""
    modified_ovpn_files = []
    for zip_path in glob.glob(f"{VPN_CONFIG_DIR}/*.zip"):
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                folder_name = os.path.splitext(os.path.basename(zip_path))[0]
                extract_dir = os.path.join(VPN_CONFIG_DIR, folder_name)
                os.makedirs(extract_dir, exist_ok=True)
                zip_ref.extractall(extract_dir)
                logging.info(f"Extracted: {zip_path}")
        except zipfile.BadZipFile:
            logging.error(f"Corrupt ZIP file: {zip_path}")
            continue

    for ovpn in glob.glob(f"{VPN_CONFIG_DIR}/**/*.ovpn", recursive=True):
        try:
            with open(ovpn, "r+") as f:
                content = f.read()
                # Insert custom configuration before the <ca> block
                ca_index = content.find("<ca>")
                if ca_index == -1:
                    logging.warning(f"No <ca> block found in {ovpn}. Skipping.")
                    continue

                custom_config = """
# Bypass VPN for real IP and RDP/SSH ports
route 77.254.229.234 255.255.255.255 net_gateway
route 0.0.0.0 255.255.255.255 net_gateway 3389
route 0.0.0.0 255.255.255.255 net_gateway 22
# Default VPN configuration
redirect-gateway def1 bypass-dhcp
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4
"""
                modified_content = content[:ca_index] + custom_config + content[ca_index:]
                f.seek(0)
                f.write(modified_content)
                f.truncate()

            modified_ovpn_files.append(ovpn)
            logging.info(f"Modified: {ovpn}")
        except Exception as e:
            logging.error(f"Error modifying {ovpn}: {e}")

    return modified_ovpn_files

def create_credentials_file(username: str, password: str, file_path: str):
    """Create a credentials file for OpenVPN."""
    try:
        with open(file_path, "w") as f:
            f.write(f"{username}\n{password}")
        logging.info(f"Created credentials file: {file_path}")
    except Exception as e:
        logging.error(f"Failed to create credentials file: {e}")

def configure_firewall():
    """Configure firewall to allow RDP and SSH traffic."""
    try:
        # Allow RDP (port 3389) and SSH (port 22)
        subprocess.run(["sudo", "ufw", "allow", "3389/tcp"], check=True)
        subprocess.run(["sudo", "ufw", "allow", "22/tcp"], check=True)
        logging.info("Firewall configured to allow RDP and SSH traffic.")
    except Exception as e:
        logging.error(f"Failed to configure firewall: {e}")

def test_vpn_latency(config_files: List[str]) -> Optional[str]:
    """Test each VPN connection and return the fastest one."""
    best_config = None
    best_time = float("inf")

    for config in config_files:
        if not config.endswith(".ovpn"):
            continue
        logging.info(f"Testing VPN: {config}")
        start_time = time.time()

        try:
            result = subprocess.run(["ping", "-c", "3", "8.8.8.8"], capture_output=True, text=True, timeout=10)
            if "time=" in result.stdout:
                avg_time = sum(float(line.split("time=")[1].split()[0]) for line in result.stdout.split("\n") if "time=" in line) / 3
                logging.info(f"Latency: {avg_time} ms")
                if avg_time < best_time:
                    best_time = avg_time
                    best_config = config
        except Exception as e:
            logging.error(f"Error testing VPN {config}: {e}")

    return best_config

def connect_to_vpn(vpn_config: str, credentials_file: str):
    """Connect to the best VPN server using OpenVPN."""
    if not vpn_config:
        logging.error("No working VPN configuration found.")
        return

    logging.info(f"Connecting to VPN: {vpn_config}")
    try:
        subprocess.run(["sudo", "openvpn", "--config", vpn_config, "--auth-user-pass", credentials_file], check=True)
    except Exception as e:
        logging.error(f"Failed to connect to VPN: {e}")

def main():
    # Initial cleanup
    cleanup()

    # Download and extract configurations
    zip_files = download_vpn_configs()
    if not zip_files:
        logging.error("No .zip files downloaded. Exiting.")
        return

    ovpn_files = extract_and_modify()
    if not ovpn_files:
        logging.error("No valid .ovpn files found. Exiting.")
        return

    # Create credentials file
    credentials_file = os.path.join(VPN_CONFIG_DIR, "auth.txt")
    create_credentials_file(VPN_USERNAME, VPN_PASSWORD, credentials_file)

    # Configure firewall
    configure_firewall()

    # Test latency and find the fastest VPN
    best_vpn = test_vpn_latency(ovpn_files)
    if best_vpn:
        logging.info(f"Fastest working VPN: {best_vpn}")
        connect_to_vpn(best_vpn, credentials_file)
    else:
        logging.error("No working VPN found.")

if __name__ == "__main__":
    main()
