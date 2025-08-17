# Ultimate VPN Connector (Self-Healing OpenVPN GUI)

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platforms](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)

**Author**: MD FAYSAL MAHMUD  
**GitHub**: [Blindsinner/OpenVPN-Automation-Script](https://github.com/Blindsinner/OpenVPN-Automation-Script)

![Ultimate VPN Connector](https://github.com/Blindsinner/OpenVPN-Automation-Script/blob/main/image.png)


## 📖 Overview

This script, `VPN_Connector.py`, is a powerful, feature-rich, and cross-platform GUI application for managing OpenVPN connections. It is designed to be a "one-click" solution that automates everything from dependency installation to finding the fastest server and connecting.

What makes this script unique is its **self-healing and intelligent design**. It automatically detects and installs its own required components, including the OpenVPN client itself, on Linux, Windows, and macOS. With advanced features like a firewall kill switch, application-specific split tunneling, and a robust, multi-platform bandwidth monitor, this tool is perfect for both beginners and power users.

*This script is intended for educational purposes and should be used responsibly within a legal and authorized environment.*

---

## 🌟 Core Features at a Glance

-   **Cross-Platform GUI**: A single, powerful interface for Windows, macOS, and Linux.
-   **Self-Healing Setup**: Automatically installs Python libraries (`requests`, `psutil`) and the OpenVPN client.
-   **Multi-Source Config Management**: Downloads and processes `.ovpn` files from multiple URLs simultaneously (e.g., from VPNBook and ProtonVPN).
-   **Smart Server Selection**: "Auto" mode pings all servers from all sources and connects to the one with the lowest latency.
-   **Multi-Profile Credentials**: Manages and tests different login credentials automatically, perfect for using multiple VPN services.
-   **Advanced Networking**: Includes a Kill Switch (Linux) and both IP-based and App-based Split Tunneling (Linux).
-   **Real-Time Monitoring**: Live dashboard shows connection status, public IP, and bandwidth usage.
-   **System Integration**: Can be configured to launch and connect on system startup.

---

## 🔧 Feature Deep Dive

This application is more than just a simple connector. Here's a detailed look at its core capabilities:

#### 🤖 Automated & Self-Healing Setup
The script is designed to run with zero manual setup. On its first launch with administrator privileges, it performs a system check. If it detects that a required Python library (`requests`, `psutil`) or even the OpenVPN program itself is missing, it will open a dialog box asking for permission to install it. This makes deployment on any new machine incredibly simple and fast.

#### ⚙️ VPN Configuration & Management
-   **URL-Based Sources**: Instead of manually downloading files, you can simply provide multiple direct download links to `.zip` archives of `.ovpn` configs in the Settings. The application handles the download, extraction, and processing for all of them in the background. It even supports Google Drive links.
-   **Easy Manual Import**: For single `.ovpn` files you have on your computer, the "Import .ovpn" button lets you add them directly. They are copied to a dedicated directory so you don't have to worry about managing the original files.
-   **Smart Processing**: Every `.ovpn` file is automatically parsed and modified to work seamlessly with the app. It standardizes the authentication method to use a secure credentials file and injects your custom DNS settings, ensuring consistency across all servers and providers.

#### 💡 Intelligent Connection & Server Selection
-   **"Auto (Best Performance)" Mode**: This is the smartest way to connect. The application runs a quick, multi-threaded latency test (ping) against every available server from all your sources. It then sorts the servers by the fastest response time and automatically begins connecting to the best one.
-   **Credential Probing**: This is a unique feature for users with multiple VPN accounts. If you have several credential profiles saved (e.g., one for ProtonVPN, one for VPNBook), the "Auto" connect mode will not only find the fastest server but will also intelligently cycle through your profiles on that server until one successfully authenticates.

#### 🛡️ Advanced Networking & Security
-   **Firewall Kill Switch (Linux)**: When enabled, this feature uses `ufw` (Uncomplicated Firewall) to create a protective barrier. It blocks *all* internet traffic by default and creates specific exceptions for the VPN tunnel. If the VPN connection drops for any reason, the internet access is instantly cut, preventing your real IP address from being exposed.
-   **IP-Based Split Tunneling**: This gives you fine-grained control over your routing table.
    -   **Exclude Mode**: The most common use case. All your traffic goes through the VPN, *except* for the IP addresses you list. This is perfect for accessing local network devices (like a printer at `192.168.1.50`) or a specific service that doesn't work with a VPN.
    -   **Include Mode**: The inverse logic. Your traffic remains on your regular internet connection, *except* for traffic destined for the IPs you list, which will be routed through the VPN.
-   **Application-Based Split Tunneling (Linux)**: This powerful Linux-only feature uses `cgroups` and `iptables` to isolate network traffic on a per-application basis. The GUI provides "Launch" buttons for your selected apps, ensuring they start within the correct network namespace to either bypass or exclusively use the VPN tunnel.

---

## ✅ Requirements

The script is designed to install most requirements for you, but you need a base system:

-   **Python 3**: Version 3.8+ is recommended.
-   **Root/Administrator Privileges**: Essential for installing software and managing network settings.
-   **For macOS users**: **Homebrew** is required for the automatic OpenVPN installation.

---

## 🚀 Installation & First Run (Cross-Platform Guide)

Because the script is self-healing, the installation is incredibly simple across all platforms.

#### Step 1: Download the Script
Clone the repository or just download the `VPN_Connector.py` script file.
```bash
git clone https://github.com/Blindsinner/OpenVPN-Automation-Script.git
cd OpenVPN-Automation-Script
```

#### Step 2: Run the Script for the First Time
You must run the script with administrator/root privileges for the self-healing and networking features to work.

-   **On Linux / macOS**:
    1.  Open a terminal in the script's directory.
    2.  Run the command:
        ```bash
        sudo python3 VPN_Connector.py
        ```

-   **On Windows**:
    1.  Search for **PowerShell** or **Command Prompt** in the Start Menu.
    2.  Right-click on it and select **"Run as Administrator"**.
    3.  Navigate to the directory where you saved the script (e.g., `cd C:\Users\YourUser\Downloads`).
    4.  Run the command:
        ```powershell
        python VPN_Connector.py
        ```

#### Step 3: Allow Automatic Installation
-   The script will now check for dependencies. If anything is missing (like `requests`, `psutil`, or OpenVPN itself), a pop-up will ask for your permission to install it.
-   Click **"Yes"** to allow the installation to proceed.
-   **Important**: After the installation finishes, **close the script and run it again** using the same command from Step 2. A restart is necessary for the new components to be recognized.

---

## 📖 How to Use the Application

#### Step 1: Get VPN Configuration Files (`.ovpn`)
The script can use `.ovpn` files from any provider. Here are two popular examples:

**Example A: Getting Files from ProtonVPN (Stable Credentials)**
1.  Go to the [ProtonVPN Account Page](https://account.protonvpn.com/login) and create a **free account**.
2.  Log in and go to the **"Downloads"** section. Select **"Linux"** as the platform.
3.  In the "OpenVPN configuration files" section, right-click the download button for **"Free server configs"** and **copy the link address**.
4.  Go to the **"Account"** section and find your **OpenVPN / IKEv2 username and password**. These are different from your login details.

**Example B: Getting Files from VPNBook (Changing Credentials)**
1.  Go to the [VPNBook Website](https://www.vpnbook.com/) and click on the **"OpenVPN"** tab.
2.  You will see several server bundles available for download (e.g., Euro Servers, US Servers). Right-click on one of the download buttons and **copy the link address**. You can copy multiple links from different bundles.
3.  **Crucially**, on that same page, VPNBook displays a **Username** and a **Password** inside a box. The password changes every few days. Make a note of the current credentials.

#### Step 2: Configure the Application
-   With the script running, click the **"Settings"** button.
    -   **Sources Tab**: Paste all the download links you want to use, one per line. For example, you can add the link from ProtonVPN *and* several links from VPNBook.
        ```
        # Example links for the Sources tab
        [https://api.protonvpn.ch/vpn/config/....zip](https://api.protonvpn.ch/vpn/config/....zip)
        [https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-ca149.zip](https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-ca149.zip)
        [https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-de20.zip](https://www.vpnbook.com/free-openvpn-account/vpnbook-openvpn-de20.zip)
        ```
    -   **Credentials Tab**: This is where you manage logins for different services.
        1.  Click **"Add"** and name the profile `Proton`. Enter your special ProtonVPN OpenVPN username and password.
        2.  Click **"Add"** again and name this one `VPNBook`. Enter the current username (usually `vpnbook`) and password from the VPNBook website.
    -   Click **"Save & Close"**. The app will download all configs, and you'll see servers from both ProtonVPN and VPNBook merged into the list.

#### Step 3: Connect to the VPN
-   **Manual Connection**: Select any server from the dropdown. The script is smart enough to try your different credential profiles until one works.
-   **Automatic Connection**: Select **"Auto (Best Performance)"** to find the fastest server available from all your sources and connect to it.
-   Click the **"Connect"** button.

The status will change to "Connecting" and then "Connected." The Public IP will update, and the bandwidth monitor will start showing live speeds.

---

## 💡 Advanced Usage & Tricks

-   **Bypassing Restrictive Firewalls**: If you are on a network that blocks most ports, go to **Settings > Connection** and set the Protocol to **TCP**. Then, in the main window, choose a server that has "tcp443" in its name. Port 443 is used for HTTPS traffic and is almost never blocked.
-   **Clearing the Cache**: The script stores all downloaded configs in a temporary directory (`/tmp/vpn_configs_ultimate` on Linux, accessible via `%temp%` on Windows). If you want to force a fresh download of all server files, you can safely delete this directory.
-   **Finding More Servers**: You can use `.ovpn` files from any provider. Search for "Free OpenVPN servers" and find providers that offer ZIP downloads of their configurations. Add the link to the **Sources** tab.
-   **Interpreting the Logs**: The color-coded log panel is your best friend for debugging.
    -   <span style="color:red">**Red (ERROR/CRITICAL)**</span>: Indicates a major failure, like a missing dependency or a connection timeout.
    -   <span style="color:orange">**Yellow (WARNING)**</span>: Indicates a non-critical issue, like an `AUTH_FAILED` (wrong password) or a failed ping to one server.
    -   <span style="color:green">**Green (SUCCESS)**</span>: Confirms a successful operation, like a connection being established.

---

## 🖱️ Creating a Double-Clickable Executable

You can convert this script into a standalone application that can be launched without a terminal for ease of use.

**First, install PyInstaller:**
```bash
pip install pyinstaller
```

#### On Kali Linux (Creating a Desktop Shortcut)
1.  **Create an Icon**: Save a suitable icon (e.g., `icon.png`) in the same directory as the script.
2.  **Create a `.desktop` File**: Create a file named `vpn-connector.desktop` on your Desktop and paste the following content into it. **Remember to replace `<path_to_your_script_folder>` with the actual absolute path.**
    ```ini
    [Desktop Entry]
    Version=1.0
    Type=Application
    Name=VPN Connector
    Comment=Ultimate OpenVPN GUI Client
    Exec=pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 <path_to_your_script_folder>/VPN_Connector.py
    Icon=<path_to_your_script_folder>/icon.png
    Terminal=false
    Categories=Network;
    ```
    *Note: `pkexec` provides a graphical password prompt, which is more user-friendly than a terminal.*
3.  **Make it Executable**: Open a terminal and run:
    ```bash
    chmod +x ~/Desktop/vpn-connector.desktop
    ```
    You can now double-click this icon. A graphical prompt will ask for your password before launching the app.

#### On Windows
1.  **Prepare**: Place an icon file (e.g., `icon.ico`) in the same folder as the script.
2.  **Run PyInstaller**: Open a **regular** Command Prompt (not as admin) in the script's folder and run:
    ```
    pyinstaller --onefile --windowed --icon="path\to\your\icon.ico" --uac-admin "path\to\OpenVPN-Automation-Script\vpn_connector.py"

    ```
    -   `--onefile`: Creates a single `.exe` file.
    -   `--windowed`: Prevents the console window from appearing behind the GUI.
3.  **Locate the Executable**: Look inside the `dist` folder that was created. You will find `VPN_Connector.exe`.
4.  **Run as Administrator**: You must **right-click** on `VPN_Connector.exe` and choose **"Run as administrator"** each time for it to work. To make this permanent, right-click the `.exe`, go to `Properties > Compatibility >` and check `Run this program as an administrator`.

#### On macOS
1.  **Prepare**: Place an icon file (e.g., `icon.icns`) in the same folder.
2.  **Run PyInstaller**: Open a terminal in the script's folder and run:
    ```bash
    pyinstaller --onefile --windowed --icon=icon.icns VPN_Connector.py
    ```
3.  **Locate the App**: Look inside the `dist` folder. You will find a `VPN_Connector.app` bundle. You can move this to your `/Applications` folder.
4.  **Run with Privileges**: When you run the app, macOS will prompt you for your administrator password because the script uses `sudo` for its network commands.

---

## 🔍 Troubleshooting
-   **`AUTH_FAILED` in logs**: This is the most common error.
    -   **For VPNBook**: Their password changes every few days. Go to their website, get the new password, and update it in your `VPNBook` profile in **Settings > Credentials**.
    -   **For ProtonVPN**: Ensure you are using the special *OpenVPN/IKEv2 credentials* from your account page, not your main login details.
-   **Executable not working**: If you create a standalone executable, ensure it is also run with administrator privileges.
-   **Connection fails on `TCP/UDP: Preserving recently used remote address`**: This means the server is likely down or unreachable from your network. Try a different server or use the "Auto" mode.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
