# OpenVPN Automation Script

**Author**: MD FAYSAL MAHMUD

This Python script automates the process of downloading, configuring, and connecting to free OpenVPN servers provided by VPNBook. It downloads VPN configuration files, extracts them, modifies them to bypass specific IPs and ports (e.g., for RDP and SSH), tests the servers for latency, and connects to the fastest one. The script is designed for educational purposes and should be used responsibly in a legal and authorized environment.

## Features
- **Automatic Download**: Fetches OpenVPN configuration files from VPNBook.
- **File Extraction and Modification**: Extracts `.ovpn` files and adds custom routes to bypass VPN for specific IPs. An Example IP is Given but you should replace with your own REAL IP (e.g., 77.254.229.234, you should put your real ip there) and ports (3389 for RDP, 22 for SSH).
- **Firewall Configuration**: Configures the system firewall to allow RDP and SSH traffic.
- **Latency Testing**: Tests each VPN server’s latency by pinging Google’s DNS (8.8.8.8) and selects the fastest one.
- **VPN Connection**: Connects to the best VPN server using OpenVPN with provided credentials.
- **Error Handling**: Includes logging for debugging and error tracking.

## Requirements
To run this script on **Kali Linux** or **Ubuntu**, you need the following:

### Software
- **Python 3**: Version 3.6 or higher (pre-installed on Kali/Ubuntu).
- **OpenVPN**: For connecting to VPN servers.
- **Unzip**: To extract `.zip` files.
- **UFW**: For firewall configuration (optional, but used by the script).
- **Ping**: For latency testing (part of `iputils-ping`).

### Python Packages
- `requests`: For downloading files.
- `urllib3`: For handling HTTPS requests.
- `zipfile`: For extracting `.zip` files (included in Python standard library).
- `subprocess`: For running system commands (included in Python standard library).
- `shutil`: For file operations (included in Python standard library).
- `logging`: For logging (included in Python standard library).
- `glob`: For file pattern matching (included in Python standard library).
- `typing`: For type hints (included in Python standard library).

### System Permissions
- **Root Privileges**: The script uses `sudo` for OpenVPN and UFW commands, so you need administrative access.

## Installation
Follow these steps to set up the environment on **Kali Linux** or **Ubuntu**:

1. **Update Your System**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Required Software**:
   ```bash
   sudo apt install -y python3 python3-pip openvpn unzip iputils-ping ufw
   ```

3. **Install Python Packages**:
   ```bash
   pip3 install requests urllib3
   ```

4. **Verify Installation**:
   - Check Python version: `python3 --version`
   - Check OpenVPN: `openvpn --version`
   - Check UFW: `ufw --version`
   - Check pip: `pip3 --version`

5. **Download the Script**:
   - Clone this repository or download `OpenVpn.py`:
     ```bash
     git clone https://github.com/Blindsinner/OpenVPN-Automation-Script.git
     cd OpenVPN-Automation-Script
     ```

## Usage
The script automates the entire process of setting up and connecting to a VPNBook OpenVPN server. Follow these steps:

### Step-by-Step Instructions
1. **Prepare the Script**:
   - Ensure `OpenVpn.py` is in your working directory.
   - Make it executable:
     ```bash
     chmod +x OpenVpn.py
     ```

2. **Update VPN Credentials**:
   - The script contains the following default VPNBook credentials:
     ```python
     VPN_USERNAME = "vpnbook"
     VPN_PASSWORD = "cf32e5w"
     ```
   - **Important**: VPNBook changes these credentials periodically (often weekly or monthly). You must update these lines in `OpenVpn.py` with the latest username and password from [vpnbook.com](https://www.vpnbook.com).
   - To update:
     1. Open `OpenVpn.py` in a text editor (e.g., `nano OpenVpn.py`).
     2. Visit [vpnbook.com](https://www.vpnbook.com) and find the current OpenVPN username and password.
     3. Replace the `VPN_USERNAME` and `VPN_PASSWORD` values in the script with the new credentials.
     4. Save and close the file.

3. **Run the Script**:
   ```bash
   sudo python3 OpenVpn.py
   ```
   - **Why `sudo`?** The script needs root privileges for OpenVPN and UFW commands.
   - You’ll be prompted for your system password.

4. **What the Script Does**:
   - Cleans up old VPN files in `/tmp/vpn_configs`.
   - Downloads `.zip` files containing `.ovpn` configurations from VPNBook.
   - Extracts and modifies `.ovpn` files to bypass VPN for:
     - IP `77.254.229.234`. (You should use your own real ip)
     - Ports 3389 (RDP) and 22 (SSH).
   - Configures the firewall to allow RDP and SSH traffic.
   - Tests each VPN server’s latency by pinging `8.8.8.8`.
   - Connects to the fastest VPN server using OpenVPN.

5. **Monitor Output**:
   - The script logs progress (e.g., downloading, extracting, connecting).
   - Example output:
     ```
     2025-06-08 21:24:35,123 - INFO - Old VPN files removed.
     2025-06-08 21:24:36,456 - INFO - Downloading: https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-ca149.zip
     2025-06-08 21:24:38,789 - INFO - Fastest working VPN: /tmp/vpn_configs/vpnbook-openvpn-ca149/vpnbook-ca149-tcp443.ovpn
     ```
   - If successful, OpenVPN will connect, and you’ll see its logs.

6. **Stop the VPN**:
   - To disconnect, press `Ctrl+C` in the terminal running the script.
   - Clean up manually if needed:
     ```bash
     sudo rm -rf /tmp/vpn_configs
     ```

## Example
```bash
sudo python3 OpenVpn.py
```
- The script downloads VPN configurations, tests them, and connects to the fastest server.
- Check your IP to confirm the VPN is working:
  ```bash
  curl ifconfig.me
  ```
- If the IP differs from your real IP, the VPN is active.

## Troubleshooting
- **Error: “No .zip files downloaded”**:
  - Check your internet connection.
  - Ensure VPNBook links in `ZIP_LINKS` are valid (visit [vpnbook.com](https://www.vpnbook.com) to confirm).
- **Error: “Failed to connect to VPN”**:
  - Verify OpenVPN is installed (`openvpn --version`).
  - Ensure the credentials in `OpenVpn.py` (`VPN_USERNAME` and `VPN_PASSWORD`) match the latest ones from [vpnbook.com](https://www.vpnbook.com).
  - Check that `auth.txt` was created in `/tmp/vpn_configs`.
- **Error: “Permission denied”**:
  - Run the script with `sudo`.
- **Error: “Ping timeout”**:
  - Some VPN servers may be down. Try running the script again.
- **Logs**: Check `/tmp/vpn_configs` for files and review terminal logs for errors.

## Important Notes
- **Credential Updates**: The script’s default VPN credentials (`VPN_USERNAME = "vpnbook"`, `VPN_PASSWORD = "cf32e5w"`) are placeholders and will not work if outdated. VPNBook updates these credentials regularly (often weekly or monthly). Before running the script, always visit [vpnbook.com](https://www.vpnbook.com) to get the latest username and password, and update the `VPN_USERNAME` and `VPN_PASSWORD` lines in `OpenVpn.py`.
- **Legal Use**: Only use this script for educational purposes or with explicit permission. Unauthorized VPN usage may violate laws or terms of service.
- **Security**: The script disables HTTPS warnings (`urllib3.disable_warnings`) for simplicity. In production, verify SSL certificates.
- **Firewall**: The script enables UFW rules for ports 3389 and 22. To reset UFW:
  ```bash
  sudo ufw reset
  ```

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make changes and commit (`git commit -m "Add your feature"`).
4. Push to your branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments
- **VPNBook**: For providing free OpenVPN configurations.
- **Python Community**: For libraries like `requests` and `urllib3`.

## Contact
For questions or issues, contact MD FAYSAL MAHMUD via [GitHub Issues](https://github.com/<your-username>/<repository-name>/issues).
