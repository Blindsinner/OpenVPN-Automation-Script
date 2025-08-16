# Ultimate VPN Connector

**Author**: MD FAYSAL MAHMUD

This Python script, `VPN_Connector.py`, provides a feature-rich, cross-platform GUI application for managing OpenVPN connections. It automates downloading, configuring, and connecting to VPN servers, with advanced features like split tunneling, a kill switch, and bandwidth monitoring. Designed for Linux, Windows, and macOS, it includes self-healing dependency management for ease of use. This script is for educational purposes and should be used responsibly in a legal and authorized environment.

## Features
- **Cross-Platform Support**: Works on Linux, Windows, and macOS with platform-specific configurations.
- **Self-Healing Dependency Management**: Automatically detects and installs missing Python libraries (`requests`, `psutil`) and OpenVPN.
- **VPN Configuration Management**:
  - Downloads `.zip` files containing `.ovpn` configurations from user-specified URLs (including Google Drive support).
  - Extracts and processes `.ovpn` files, adding custom DNS and credentials.
  - Supports importing custom `.ovpn` files.
- **Server Selection**:
  - Displays available VPN servers in a GUI dropdown with filtering and favoriting.
  - "Auto (Best Performance)" mode pings servers and connects to the fastest one.
- **Credential Management**:
  - Supports multiple credential profiles for different VPN servers.
  - Securely stores credentials with restricted permissions.
- **Connection Management**:
  - Supports UDP, TCP, or automatic protocol selection.
  - Auto-reconnects on connection drops (configurable).
  - Displays real-time connection status and public IP.
- **Split Tunneling**:
  - **IP Split Tunneling**: Routes specific IPs/subnets to bypass or use the VPN (exclude/include modes).
  - **App Split Tunneling** (Linux only): Routes traffic from specific applications to bypass or use the VPN.
- **Firewall Kill Switch** (Linux only): Uses `ufw` to block all traffic except through the VPN interface.
- **Bandwidth Monitoring**: Displays upload/download speeds for the VPN interface.
- **Auto-Start and Auto-Connect**:
  - Configures the application to start with the system.
  - Optionally connects to a VPN server on startup.
- **Logging**: Detailed, color-coded logs in the GUI and a log file for debugging.
- **Error Handling**: Robust handling of network issues, missing dependencies, and permission errors.

## Requirements
To run this script, you need:

### Software
- **Python 3**: Version 3.6 or higher (pre-installed on most Linux/macOS systems).
- **OpenVPN**: For connecting to VPN servers.
- **tkinter**: For the GUI (usually included with Python).
- **Unzip**: For extracting `.zip` files (Linux/macOS).
- **UFW**: For the kill switch (Linux only, optional).
- **Ping**: For latency testing (part of `iputils-ping` on Linux).
- **Homebrew**: For OpenVPN installation on macOS (optional).

### Python Packages
- `requests`: For downloading files.
- `psutil`: For bandwidth monitoring and interface detection.
- `tkinter`, `zipfile`, `shutil`, `logging`, `subprocess`, `glob`, `json`, `tempfile`, `re`, `queue`, `socket`: Included in the Python standard library.
- Platform-specific: `winreg` (Windows), `plistlib` (macOS).

### System Permissions
- **Root/Administrator Privileges**: Required for managing network routes, firewall rules, and installing dependencies.

## Installation
Follow these steps to set up the environment:

### Linux (Ubuntu/Kali)
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
   pip3 install requests psutil
   ```
4. **Verify Installation**:
   - Python: `python3 --version`
   - OpenVPN: `openvpn --version`
   - UFW (optional): `ufw --version`
   - pip: `pip3 --version`

### Windows
1. Ensure Python 3 is installed (`python --version`).
2. The script will attempt to install OpenVPN automatically if missing.
3. Install Python packages:
   ```bash
   pip install requests psutil
   ```

### macOS
1. Install Homebrew (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
2. Install dependencies:
   ```bash
   brew install python openvpn
   ```
3. Install Python packages:
   ```bash
   pip3 install requests psutil
   ```

### Download the Script
- Clone the repository or download `VPN_Connector.py`:
  ```bash
  git clone https://github.com/Blindsinner/OpenVPN-Automation-Script.git
  cd OpenVPN-Automation-Script
  ```

## Usage
The script provides a GUI to manage OpenVPN connections. Follow these steps:

### Step-by-Step Instructions
1. **Prepare the Script**:
   - Ensure `VPN_Connector.py` is in your working directory.
   - Make it executable (Linux/macOS):
     ```bash
     chmod +x VPN_Connector.py
     ```

2. **Run the Script**:
   - **Linux/macOS**:
     ```bash
     sudo python3 VPN_Connector.py
     ```
   - **Windows** (run as Administrator):
     ```bash
     python VPN_Connector.py
     ```
   - **Note**: `sudo` or Administrator rights are required for network and firewall operations.

3. **Initial Setup**:
   - The script checks for missing dependencies and prompts to install them if needed.
   - Restart the script after any dependency installation.

4. **Configure Settings**:
   - Open the "Settings" window from the GUI to:
     - **Credentials**: Add/edit credential profiles (username/password) for VPN servers.
     - **Connection**: Set protocol (UDP/TCP/Auto), custom DNS, auto-reconnect, auto-start, and auto-connect.
     - **Sources**: Add URLs for `.zip` files containing `.ovpn` configurations (e.g., from VPNBook).
     - **IP Split Tunneling**: Specify IPs/subnets to bypass or use the VPN.
     - **App Split Tunneling** (Linux only): Select applications to bypass or use the VPN.
     - **Firewall** (Linux only): Enable the kill switch.

5. **Connect to a VPN**:
   - Select a server from the dropdown or choose "Auto (Best Performance)" to connect to the fastest server.
   - Click "Connect" to initiate the connection.
   - Monitor connection status, public IP, and bandwidth in the GUI.
   - Use the "Import .ovpn" button to add custom configuration files.

6. **Stop/Disconnect**:
   - Click "Stop" to cancel a connection attempt.
   - Click "Disconnect" to terminate an active VPN connection.
   - To exit, close the GUI window (automatically disconnects).

7. **Verify Connection**:
   - Check your public IP in the GUI or via:
     ```bash
     curl ifconfig.me
     ```
   - If the IP differs from your real IP, the VPN is active.

## Example
```bash
sudo python3 VPN_Connector.py
```
- The GUI opens, allowing you to configure settings, select servers, and connect.
- Logs are displayed in the GUI and saved to `/tmp/vpn_connector.log`.

## Troubleshooting
- **Error: "Admin Rights Required"**:
  - Run with `sudo` (Linux/macOS) or as Administrator (Windows).
- **Error: "Dependencies Missing"**:
  - Allow the script to install missing libraries or OpenVPN, then restart.
  - Manually install: `pip install requests psutil` or system-specific OpenVPN packages.
- **Error: "No VPN ZIP links configured"**:
  - Add `.zip` URLs in the Settings > Sources tab (e.g., from [vpnbook.com](https://www.vpnbook.com)).
- **Error: "Failed to connect to VPN"**:
  - Verify credentials in the Settings > Credentials tab (update from VPN provider).
  - Ensure OpenVPN is installed (`openvpn --version`).
  - Check `/tmp/vpn_configs/auth.txt` for correct credentials.
- **Error: "Ping timeout"**:
  - Some servers may be down; try "Auto" mode or different servers.
- **Logs**: Check `/tmp/vpn_connector.log` or the GUI log area for details.

## Important Notes
- **Credentials**: Update credentials in the Settings > Credentials tab to match your VPN provider’s latest username/password (e.g., from [vpnbook.com](https://www.vpnbook.com)).
- **Protocol**: Use TCP or UDP as specified by your VPN provider (configurable in Settings > Connection).
- **Legal Use**: Use this script only for educational purposes or with explicit permission. Unauthorized VPN usage may violate laws or terms of service.
- **Security**: The script disables HTTPS warnings for simplicity. In production, verify SSL certificates.
- **Firewall**: The kill switch (Linux only) uses `ufw`. To reset:
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
- **Python Community**: For libraries like `requests`, `psutil`, and `tkinter`.

## Contact
For questions or issues, contact MD FAYSAL MAHMUD via [GitHub Issues](https://github.com/Blindsinner/OpenVPN-Automation-Script/issues).
