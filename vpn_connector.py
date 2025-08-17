import os
import sys
import time
import subprocess
import glob
import zipfile
import shutil
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
import json
import tempfile
import re
import queue
import socket
import random

# --- Self-Healing Dependency Management ---
# Attempt to import required libraries. They will be installed if missing.
try:
    import requests
    import psutil
except ImportError:
    requests = None
    psutil = None

# --- Platform Detection & Configuration ---
if sys.platform == "win32":
    import winreg

if sys.platform == "darwin":
    from plistlib import dumps as plist_dump

PLATFORM_DETAILS = {
    'linux': { 'name': 'linux', 'ping_cmd': ["ping", "-c", "3", "-W", "5"], 'ping_pattern': r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", 'sudo_prefix': ["sudo"], 'kill_cmd': ["killall", "-SIGTERM", "openvpn"], 'creationflags': 0, 'get_gateway_cmd': ["ip", "route", "show", "default"], 'gateway_pattern': r"default via ([\d\.]+) dev ([\w\d\.-]+)", 'vpn_gateway_cmd': ["ip", "route", "show", "dev", "tun0"], 'vpn_gateway_pattern': r"0\.0\.0\.0/1\s+via\s+([\d\.]+)" },
    'windows': { 'name': 'windows', 'ping_cmd': ["ping", "-n", "3", "-w", "5000"], 'ping_pattern': r"Average = (\d+)ms", 'sudo_prefix': [], 'kill_cmd': None, 'creationflags': subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0, 'get_gateway_cmd': ["route", "print", "-4"], 'gateway_pattern': r"0\.0\.0\.0\s+0\.0\.0\.0\s+([\d\.]+)", 'vpn_gateway_cmd': ["route", "print", "-4"], 'vpn_gateway_pattern': r"0\.0\.0\.0\s+0\.0\.0\.0\s+([\d\.]+)\s+([\d\.]+)\s+\d+" },
    'macos': { 'name': 'macos', 'ping_cmd': ["ping", "-c", "3", "-W", "5"], 'ping_pattern': r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", 'sudo_prefix': ["sudo"], 'kill_cmd': ["killall", "-SIGTERM", "openvpn"], 'creationflags': 0, 'get_gateway_cmd': ["netstat", "-nr"], 'gateway_pattern': r"^default\s+([\d\.]+)", 'vpn_gateway_pattern': r"^default\s+[\d\.]+\s+[\w\s]+\s+tun0" }
}

def get_platform():
    if sys.platform.startswith('linux'): return PLATFORM_DETAILS['linux']
    elif sys.platform == 'win32': return PLATFORM_DETAILS['windows']
    elif sys.platform == 'darwin': return PLATFORM_DETAILS['macos']
    else:
        try:
            messagebox.showerror("Unsupported Platform", f"Your platform '{sys.platform}' is not supported.")
        except tk.TclError:
            print(f"ERROR: Unsupported Platform '{sys.platform}'")
        sys.exit(1)

PLATFORM_CONFIG = get_platform()
PLATFORM = PLATFORM_CONFIG['name']

# --- Constants, Config, Logging ---
VPN_CONFIG_DIR = os.path.join(tempfile.gettempdir(), "vpn_configs_ultimate")
LOG_FILE_PATH = os.path.join(tempfile.gettempdir(), "vpn_connector.log")
CONFIG_FILE = os.path.join(tempfile.gettempdir(), "vpn_config.json")
CUSTOM_CONFIG_DIR = os.path.join(tempfile.gettempdir(), ".vpn_connector_custom_configs")
OPENVPN_WINDOWS_INSTALLER_URL = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.10-I001-amd64.msi"

def setup_logging():
    try:
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE_PATH, encoding='utf-8', mode='w'),
                logging.StreamHandler()
            ]
        )
    except PermissionError as e:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        logging.warning(f"Failed to write to log file {LOG_FILE_PATH}: {e}. Logging to console only.")
    except Exception as e:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        logging.error(f"Logging setup failed: {e}. Falling back to console logging.")

setup_logging()
if psutil and requests: # Only disable warnings if requests was successfully imported
    if hasattr(requests.packages, 'urllib3'):
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def is_admin():
    if PLATFORM in ('linux', 'macos'): return os.geteuid() == 0
    elif PLATFORM == 'windows':
        try: import ctypes; return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (ImportError, AttributeError): return False
    return False

class SettingsWindow(tk.Toplevel):
    def __init__(self, master_app):
        super().__init__(master_app.root)
        self.transient(master_app.root)
        self.title("Ultimate VPN Settings")
        self.app = master_app
        self.geometry("600x600")
        self.resizable(False, False)
        style = ttk.Style(self)
        style.configure("TNotebook.Tab", padding=[10, 5], font=('TkDefaultFont', 10, 'bold'))
        main_frame = ttk.Frame(self, padding="10"); main_frame.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(main_frame); notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        cred_tab, conn_tab, sources_tab, split_tunnel_tab, app_tunnel_tab, firewall_tab = (ttk.Frame(notebook, padding="10") for _ in range(6))
        notebook.add(cred_tab, text="Credentials"); notebook.add(conn_tab, text="Connection"); notebook.add(sources_tab, text="Sources"); notebook.add(split_tunnel_tab, text="IP Split Tunneling"); notebook.add(app_tunnel_tab, text="App Split Tunneling"); notebook.add(firewall_tab, text="Firewall (Linux)")
        self.create_credentials_tab(cred_tab); self.create_connection_tab(conn_tab); self.create_sources_tab(sources_tab); self.create_split_tunneling_tab(split_tunnel_tab); self.create_app_tunneling_tab(app_tunnel_tab); self.create_firewall_tab(firewall_tab)
        self.save_button = ttk.Button(main_frame, text="Save & Close", command=self.save_and_close); self.save_button.pack(pady=10)
    def create_credentials_tab(self, tab):
        self.credential_profiles = self.app.settings.get("credential_profiles", {}).copy()
        profile_frame = ttk.LabelFrame(tab, text="Credential Profiles", padding="10"); profile_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(profile_frame, text="Profile:").grid(row=0, column=0, padx=(0, 5), sticky=tk.W)
        self.profile_var = tk.StringVar()
        self.profile_menu = ttk.Combobox(profile_frame, textvariable=self.profile_var, state="readonly"); self.profile_menu.grid(row=0, column=1, sticky=tk.EW, padx=5); self.profile_menu.bind("<<ComboboxSelected>>", self.on_profile_select)
        ttk.Button(profile_frame, text="Add", command=self.add_profile).grid(row=0, column=2, padx=5)
        ttk.Button(profile_frame, text="Remove", command=self.remove_profile).grid(row=0, column=3, padx=5)
        profile_frame.columnconfigure(1, weight=1)
        details_frame = ttk.LabelFrame(tab, text="Profile Details", padding="10"); details_frame.pack(fill=tk.X)
        ttk.Label(details_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar(); self.username_entry = ttk.Entry(details_frame, textvariable=self.username_var, width=40); self.username_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        ttk.Label(details_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar(); self.password_entry = ttk.Entry(details_frame, textvariable=self.password_var, show="*"); self.password_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        details_frame.columnconfigure(1, weight=1)
        self.username_var.trace_add("write", self.on_details_change); self.password_var.trace_add("write", self.on_details_change)
        self.update_profile_list()
    def update_profile_list(self):
        profiles = list(self.credential_profiles.keys()); self.profile_menu['values'] = profiles
        if profiles: self.profile_var.set(profiles[0])
        else: self.profile_var.set("")
        self.on_profile_select()
    def on_profile_select(self, event=None):
        profile_name = self.profile_var.get()
        if profile_name in self.credential_profiles:
            creds = self.credential_profiles[profile_name]
            self.username_var.set(creds.get("username", "")); self.password_var.set(creds.get("password", ""))
            for entry in [self.username_entry, self.password_entry]: entry.config(state=tk.NORMAL)
        else:
            self.username_var.set(""); self.password_var.set("")
            for entry in [self.username_entry, self.password_entry]: entry.config(state=tk.DISABLED)
    def on_details_change(self, *args):
        if profile_name := self.profile_var.get(): self.credential_profiles[profile_name] = {"username": self.username_var.get(), "password": self.password_var.get()}
    def add_profile(self):
        if (new_name := simpledialog.askstring("New Profile", "Enter a name for the new profile:", parent=self)) and new_name not in self.credential_profiles:
            self.credential_profiles[new_name] = {"username": "", "password": ""}; self.update_profile_list(); self.profile_var.set(new_name)
        elif new_name: messagebox.showwarning("Duplicate Name", f"A profile named '{new_name}' already exists.", parent=self)
    def remove_profile(self):
        profile_name = self.profile_var.get()
        if len(self.credential_profiles) > 1 and profile_name and messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{profile_name}'?", parent=self):
            del self.credential_profiles[profile_name]; self.update_profile_list()
        elif len(self.credential_profiles) <= 1: messagebox.showwarning("Cannot Delete", "You must have at least one profile.", parent=self)
    def create_connection_tab(self, tab):
        ttk.Label(tab, text="Protocol:", font=("TkDefaultFont", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=5); self.protocol_var = tk.StringVar(value=self.app.settings.get("protocol", "auto")); ttk.Combobox(tab, textvariable=self.protocol_var, values=["auto", "udp", "tcp"], state="readonly").grid(row=0, column=1, sticky=tk.EW)
        ttk.Label(tab, text="Custom DNS (comma-separated):", font=("TkDefaultFont", 10, "bold")).grid(row=1, column=0, sticky=tk.W, pady=5); self.dns_var = tk.StringVar(value=",".join(self.app.settings.get("custom_dns", ["8.8.8.8", "8.8.4.4"]))); ttk.Entry(tab, textvariable=self.dns_var).grid(row=1, column=1, sticky=tk.EW)
        self.reconnect_var = tk.BooleanVar(value=self.app.settings.get("auto_reconnect", True)); ttk.Checkbutton(tab, text="Auto-reconnect on drop", variable=self.reconnect_var).grid(row=2, columnspan=2, sticky=tk.W, pady=10)
        self.auto_start_var = tk.BooleanVar(value=self.app.settings.get("auto_start", False)); ttk.Checkbutton(tab, text="Start with system", variable=self.auto_start_var).grid(row=3, columnspan=2, sticky=tk.W, pady=10)
        self.auto_connect_var = tk.BooleanVar(value=self.app.settings.get("auto_connect", False)); ttk.Checkbutton(tab, text="Auto connect on start", variable=self.auto_connect_var).grid(row=4, columnspan=2, sticky=tk.W, pady=10)
        tab.columnconfigure(1, weight=1)
    def create_sources_tab(self, tab):
        ttk.Label(tab, text="VPN ZIP Links (one per line):", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W); self.links_text = tk.Text(tab, height=10, width=60, relief=tk.SOLID, borderwidth=1); self.links_text.pack(fill=tk.BOTH, expand=True, pady=5); self.links_text.insert("1.0", "\n".join(self.app.settings.get("vpn_zip_links", [])))
    def create_split_tunneling_tab(self, tab):
        self.split_tunnel_mode = tk.StringVar(value=self.app.settings.get("split_tunnel_mode", "off")); mode_frame = ttk.LabelFrame(tab, text="IP Split Tunneling Mode", padding="10"); mode_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Radiobutton(mode_frame, text="Disabled", variable=self.split_tunnel_mode, value="off").pack(anchor=tk.W); ttk.Radiobutton(mode_frame, text="Bypass VPN for IPs below (Exclude Mode)", variable=self.split_tunnel_mode, value="exclude").pack(anchor=tk.W); ttk.Radiobutton(mode_frame, text="Only use VPN for IPs below (Include Mode)", variable=self.split_tunnel_mode, value="include").pack(anchor=tk.W)
        ttk.Label(tab, text="This feature allows specific network traffic to bypass or exclusively use the VPN.", wraplength=550, justify=tk.LEFT).pack(anchor=tk.W, fill=tk.X, pady=5)
        ips_frame = ttk.LabelFrame(tab, text="IPs / Subnets (one per line)", padding="10"); ips_frame.pack(fill=tk.BOTH, expand=True, pady=(10,0)); ttk.Label(ips_frame, text="Examples: 8.8.8.8 (Google DNS), 192.168.0.0/24 (Local Subnet)", foreground="gray").pack(anchor=tk.W)
        self.split_tunnel_ips_text = tk.Text(ips_frame, height=8, width=50, relief=tk.SOLID, borderwidth=1); self.split_tunnel_ips_text.pack(fill=tk.BOTH, expand=True, pady=5); self.split_tunnel_ips_text.insert("1.0", "\n".join(self.app.settings.get("split_tunnel_ips", ["192.168.0.0/16", "10.0.0.0/8"])))
    def create_app_tunneling_tab(self, tab):
        if PLATFORM != 'linux':
            ttk.Label(tab, text="App-based split tunneling is currently only supported on Linux.", foreground="orange").pack(pady=10)
            return
        self.app_split_mode = tk.StringVar(value=self.app.settings.get("app_split_mode", "off"))
        mode_frame = ttk.LabelFrame(tab, text="App Split Tunneling Mode", padding="10"); mode_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Radiobutton(mode_frame, text="Disabled", variable=self.app_split_mode, value="off").pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="Bypass VPN for apps below (Exclude Mode)", variable=self.app_split_mode, value="exclude").pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="Only use VPN for apps below (Include Mode)", variable=self.app_split_mode, value="include").pack(anchor=tk.W)
        apps_frame = ttk.LabelFrame(tab, text="Applications (executable paths)", padding="10"); apps_frame.pack(fill=tk.BOTH, expand=True, pady=(10,0))
        self.apps_listbox = tk.Listbox(apps_frame, height=8)
        self.apps_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        for app in self.app.settings.get("split_tunnel_apps", []): self.apps_listbox.insert(tk.END, app)
        btn_frame = ttk.Frame(apps_frame); btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Add", command=self.add_app).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Remove", command=self.remove_app).pack(side=tk.LEFT, padx=5)
    def add_app(self):
        path = filedialog.askopenfilename(title="Select Application", filetypes=[("Executables", "*"), ("All files", "*.*")])
        if path and path not in self.apps_listbox.get(0, tk.END): self.apps_listbox.insert(tk.END, path)
    def remove_app(self):
        sel = self.apps_listbox.curselection()
        if sel: self.apps_listbox.delete(sel[0])
    def create_firewall_tab(self, tab):
        is_linux = PLATFORM == "linux"; fw_state = tk.NORMAL if is_linux else tk.DISABLED
        self.kill_switch_var = tk.BooleanVar(value=self.app.settings.get("kill_switch", False)); ttk.Checkbutton(tab, text="Enable Firewall Kill Switch (Linux/ufw only)", variable=self.kill_switch_var, state=fw_state).pack(anchor=tk.W, pady=5)
        if not is_linux: ttk.Label(tab, text="Firewall features require 'ufw' on Linux and admin rights.", foreground="orange").pack(anchor=tk.W, pady=10)
    def save_and_close(self):
        self.app.settings.update({
            "credential_profiles": self.credential_profiles,
            "protocol": self.protocol_var.get(),
            "custom_dns": [dns.strip() for dns in self.dns_var.get().split(',') if dns.strip()],
            "auto_reconnect": self.reconnect_var.get(),
            "vpn_zip_links": [line.strip() for line in self.links_text.get("1.0", tk.END).strip().split('\n') if line.strip()],
            "split_tunnel_mode": self.split_tunnel_mode.get(),
            "split_tunnel_ips": [line.strip() for line in self.split_tunnel_ips_text.get("1.0", tk.END).strip().split('\n') if line.strip()],
            "app_split_mode": self.app_split_mode.get() if PLATFORM == 'linux' else "off",
            "split_tunnel_apps": list(self.apps_listbox.get(0, tk.END)) if PLATFORM == 'linux' else [],
            "kill_switch": self.kill_switch_var.get() if PLATFORM == 'linux' else False,
            "auto_start": self.auto_start_var.get(),
            "auto_connect": self.auto_connect_var.get()
        })
        self.app.save_settings(); self.app.log("Settings saved."); self.destroy()

class VPNConnectorApp:
    def __init__(self, root, openvpn_path):
        self.root = root; self.root.title("Ultimate VPN Connector"); self.root.geometry("900x700"); self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.vpn_process = None; self.is_connected = False; self.is_connecting = False; self.vpn_servers = {}; self.favorites = set(); self.log_queue = queue.Queue(); self.stop_connecting_event = threading.Event(); self.stop_bw_monitor = threading.Event()
        self.original_gateway = None; self.original_iface = None; self.vpn_gateway = None; self.active_routes = []; self.openvpn_executable_path = openvpn_path; self.vpn_interface_name = None
        self.app_split_setup = False
        self.up_interfaces_before_connect = set()
        self.active_config_path = None
        self.active_server_name = None
        self.load_settings(); self.create_widgets(); self.root.after(100, self.process_log_queue); threading.Thread(target=self.initial_setup, daemon=True).start()

    def create_widgets(self):
        self.main_frame = ttk.Frame(self.root, padding="10"); self.main_frame.pack(fill=tk.BOTH, expand=True)
        top_frame = ttk.Frame(self.main_frame); top_frame.pack(fill=tk.X, pady=5)
        server_frame = ttk.LabelFrame(top_frame, text="Server Selection", padding="10"); server_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.filter_var = tk.StringVar(); self.filter_var.trace_add("write", self.update_server_list_from_filter); ttk.Entry(server_frame, textvariable=self.filter_var, width=20).pack(side=tk.LEFT, padx=(0,5))
        self.server_var = tk.StringVar(value="Auto (Best Performance)"); self.server_menu = ttk.Combobox(server_frame, textvariable=self.server_var, state='disabled'); self.server_menu.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.fav_button = ttk.Button(server_frame, text="☆", command=self.toggle_favorite, width=3); self.fav_button.pack(side=tk.LEFT)
        control_frame = ttk.Frame(top_frame); control_frame.pack(side=tk.LEFT)
        self.connect_button = ttk.Button(control_frame, text="Connect", command=self.start_vpn_thread, state=tk.DISABLED); self.connect_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_connection_attempt, state=tk.DISABLED); self.stop_button.pack(side=tk.LEFT, padx=5)
        self.import_button = ttk.Button(control_frame, text="Import .ovpn", command=self.import_ovpn_file); self.import_button.pack(side=tk.LEFT, padx=5)
        self.disconnect_button = ttk.Button(control_frame, text="Disconnect", command=self.disconnect_vpn, state=tk.DISABLED); self.disconnect_button.pack(side=tk.LEFT, padx=5)
        settings_button = ttk.Button(top_frame, text="Settings", command=self.open_settings); settings_button.pack(side=tk.RIGHT)
        status_panel = ttk.Frame(self.main_frame); status_panel.pack(fill=tk.X, pady=5)
        self.status_label = ttk.Label(status_panel, text="Status: Initializing...", foreground="orange", font=("TkDefaultFont", 10, "bold")); self.status_label.pack(side=tk.LEFT)
        self.bw_label = ttk.Label(status_panel, text="BW: 0.0 KB/s ↓ 0.0 KB/s ↑"); self.bw_label.pack(side=tk.RIGHT, padx=10)
        ip_frame = ttk.Frame(status_panel); ip_frame.pack(side=tk.RIGHT)
        self.ip_label = ttk.Label(ip_frame, text="Public IP: N/A"); self.ip_label.pack(side=tk.LEFT)
        self.refresh_ip_button = ttk.Button(ip_frame, text="⟳", width=2, command=lambda: threading.Thread(target=self.update_public_ip, daemon=True).start()); self.refresh_ip_button.pack(side=tk.LEFT, padx=(5,0)); self.refresh_ip_button.config(state=tk.DISABLED)
        self.split_apps_frame = ttk.LabelFrame(self.main_frame, text="Split Tunnel Apps", padding="10")
        log_frame = ttk.LabelFrame(self.main_frame, text="Logs", padding="10"); log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        log_control_frame = ttk.Frame(log_frame); log_control_frame.pack(fill=tk.X, pady=(0, 5)); ttk.Button(log_control_frame, text="Copy Log", command=self.copy_logs_to_clipboard).pack(side=tk.RIGHT)
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, state=tk.DISABLED, bg="#2b2b2b", fg="#a9b7c6"); self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.tag_configure("SUCCESS", foreground="#6a8759"); self.log_area.tag_configure("ERROR", foreground="#ff6b68"); self.log_area.tag_configure("CRITICAL", foreground="#ff6b68", font=("TkDefaultFont", 9, "bold")); self.log_area.tag_configure("WARNING", foreground="#ffc66d"); self.log_area.tag_configure("INFO", foreground="#a9b7c6")

    def populate_split_apps_frame(self):
        for widget in self.split_apps_frame.winfo_children():
            widget.destroy()
        for app in self.settings.get("split_tunnel_apps", []):
            frame = ttk.Frame(self.split_apps_frame)
            ttk.Label(frame, text=os.path.basename(app)).pack(side=tk.LEFT, padx=5)
            ttk.Button(frame, text="Launch", command=lambda a=app: self.launch_split_app(a)).pack(side=tk.LEFT)
            frame.pack(fill=tk.X, pady=2)

    def launch_split_app(self, path):
        try:
            if not self.app_split_setup:
                self.log("Cannot launch with split tunneling: The feature is not active.", "ERROR")
                return
            user = os.getlogin()
            cmd = ['sudo', 'ip', 'netns', 'exec', 'appsplit_ns', 'sudo', '-u', user, path]
            subprocess.Popen(cmd)
            self.log(f"Launched {os.path.basename(path)} inside network namespace.", "SUCCESS")
        except Exception as e:
            self.log(f"Failed to launch {path} in namespace: {e}", "ERROR")

    def process_log_queue(self):
        while not self.log_queue.empty():
            log_entry, level = self.log_queue.get()
            self.log_area.config(state=tk.NORMAL); self.log_area.insert(tk.END, log_entry + "\n", level); self.log_area.config(state=tk.DISABLED); self.log_area.see(tk.END)
        self.root.after(100, self.process_log_queue)

    def log(self, message: str, level: str = "INFO"):
        logging.info(f"[{level}] {message}"); self.log_queue.put((f"[{level}] {message}", level))

    def copy_logs_to_clipboard(self):
        try: self.root.clipboard_clear(); self.root.clipboard_append(self.log_area.get("1.0", tk.END)); self.log("Log content copied.", "SUCCESS")
        except Exception as e: self.log(f"Failed to copy log: {e}", "ERROR")

    def get_default_settings(self):
        return { "credential_profiles": {"Default": {"username":"", "password":""}}, "protocol": "auto", "custom_dns": ["8.8.8.8", "8.8.4.4"], "auto_reconnect": True, "vpn_zip_links": [], "favorites": [], "split_tunnel_mode": "off", "split_tunnel_ips": ["192.168.0.0/16", "10.0.0.0/8"], "app_split_mode": "off", "split_tunnel_apps": [], "kill_switch": False, "auto_start": False, "auto_connect": False }

    def load_settings(self):
        try:
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, 'r') as f: self.settings = json.load(f)
            for key, value in self.get_default_settings().items(): self.settings.setdefault(key, value)
            self.favorites = set(self.settings.get("favorites", []))
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            self.settings = self.get_default_settings(); self.favorites = set()
            self.log(f"Failed to load settings from {CONFIG_FILE}. Using defaults.", "WARNING")

    def save_settings(self):
        self.settings["favorites"] = sorted(list(self.favorites))
        try:
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, 'w') as f: json.dump(self.settings, f, indent=4)
            if PLATFORM != 'windows': os.chmod(CONFIG_FILE, 0o600)
            self.set_auto_start(self.settings["auto_start"])
        except (IOError, PermissionError) as e: self.log(f"Failed to save settings to {CONFIG_FILE}: {e}", "ERROR")

    def set_auto_start(self, enable):
        app_name = "VPNConnector"
        app_path = f'"{sys.executable}" "{os.path.abspath(__file__)}"'
        if PLATFORM == "windows":
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                if enable:
                    winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, app_path)
                else:
                    try: winreg.DeleteValue(key, app_name)
                    except FileNotFoundError: pass
                winreg.CloseKey(key)
            except Exception as e:
                self.log(f"Failed to set auto start on Windows: {e}", "ERROR")
        elif PLATFORM == "linux":
            autostart_dir = os.path.expanduser("~/.config/autostart")
            os.makedirs(autostart_dir, exist_ok=True)
            desktop_file = os.path.join(autostart_dir, f"{app_name}.desktop")
            if enable:
                try:
                    with open(desktop_file, "w") as f:
                        f.write(f"[Desktop Entry]\nType=Application\nExec={app_path}\nHidden=false\nNoDisplay=false\nX-GNOME-Autostart-enabled=true\nName={app_name}\n")
                    os.chmod(desktop_file, 0o644)
                except Exception as e: self.log(f"Failed to set auto start on Linux: {e}", "ERROR")
            else:
                if os.path.exists(desktop_file): os.remove(desktop_file)
        elif PLATFORM == "macos":
            launch_dir = os.path.expanduser("~/Library/LaunchAgents")
            os.makedirs(launch_dir, exist_ok=True)
            plist_file = os.path.join(launch_dir, f"com.{app_name.lower()}.plist")
            if enable:
                try:
                    plist = {
                        "Label": f"com.{app_name.lower()}",
                        "ProgramArguments": [sys.executable, os.path.abspath(__file__)],
                        "RunAtLoad": True,
                        "KeepAlive": False
                    }
                    with open(plist_file, "wb") as f:
                        plist_dump(plist, f)
                    os.chmod(plist_file, 0o644)
                    subprocess.run(["launchctl", "load", plist_file], check=False)
                except Exception as e: self.log(f"Failed to set auto start on macOS: {e}", "ERROR")
            else:
                subprocess.run(["launchctl", "unload", plist_file], check=False)
                if os.path.exists(plist_file): os.remove(plist_file)

    def open_settings(self):
        if self.is_connecting or self.is_connected: messagebox.showwarning("Warning", "Cannot change settings while connected.")
        else: SettingsWindow(self)

    def start_vpn_thread(self):
        if psutil:
            self.up_interfaces_before_connect = {
                name for name, stats in psutil.net_if_stats().items() if stats.isup
            }
        if self.is_connecting or self.is_connected: return
        profiles = self.settings.get("credential_profiles", {})
        if not any(p.get("username") and p.get("password") for p in profiles.values()):
            messagebox.showerror("Credentials Missing", "Please configure a username and password in Settings."); return
        self.stop_connecting_event.clear(); self.is_connecting = True
        self.original_gateway, self.original_iface = self.get_default_gateway()
        for button in [self.connect_button, self.server_menu, self.disconnect_button]: button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL); self.status_label.config(text="Status: Connecting...", foreground="orange")
        threading.Thread(target=self.run_vpn_procedure, daemon=True).start()

    def stop_connection_attempt(self):
        self.log("Stop button clicked.", "WARNING"); self.stop_connecting_event.set()
        if self.vpn_process: self.disconnect_vpn()
        else: self.reset_ui_to_disconnected()

    def initial_setup(self):
        try:
            self.log("Performing initial setup...")
            os.makedirs(CUSTOM_CONFIG_DIR, exist_ok=True); self.cleanup(); self.download_vpn_configs(); self.extract_zip_files(); self.load_all_ovpn_configs()
            self.root.after(0, self.update_server_list_from_filter); self.root.after(0, lambda: self.connect_button.config(state=tk.NORMAL)); self.root.after(0, lambda: self.status_label.config(text="Status: Ready", foreground="blue"))
            self.log("Setup complete. Ready to connect.")
            if self.settings["auto_connect"]:
                self.start_vpn_thread()
        except Exception as e:
            self.log(f"Initial setup failed: {e}", "CRITICAL"); self.root.after(0, lambda: self.status_label.config(text="Status: Setup Failed!", foreground="red"))

    def run_vpn_procedure(self):
        try:
            selected_server_name = self.server_var.get(); connection_successful = False
            all_profiles = self.settings.get("credential_profiles", {})
            complete_profiles = {name: creds for name, creds in all_profiles.items() if creds.get("username") and creds.get("password")}
            profile_names = list(complete_profiles.keys())
            self.log(f"Found {len(profile_names)} complete credential profile(s) to probe with: {profile_names}")
            if not profile_names:
                self.log("No complete credential profiles found.", "ERROR"); self.root.after(0, self.reset_ui_to_disconnected); return
            
            server_list_to_try = []
            if selected_server_name == "Auto (Best Performance)":
                server_list_to_try = self.find_best_servers(limit=None)
                if not server_list_to_try: self.log("No responsive servers found.", "ERROR"); self.root.after(0, self.reset_ui_to_disconnected); return
                self.log(f"Found {len(server_list_to_try)} responsive servers. Beginning smart connect probe...")
            else:
                vpn_config_path = self.vpn_servers.get(selected_server_name)
                if not vpn_config_path: self.log("Selected server not found.", "ERROR"); self.root.after(0, self.reset_ui_to_disconnected); return
                protocol = self._infer_protocol_from_filename(selected_server_name)
                server_list_to_try.append((vpn_config_path, selected_server_name, protocol))

            for config_path, server_name, protocol in server_list_to_try:
                if self.stop_connecting_event.is_set(): break
                self.log(f"--- Trying server: {server_name} ---")
                
                self.active_config_path = config_path
                self.active_server_name = server_name
                
                if self.settings["kill_switch"] and PLATFORM == "linux":
                    self.disable_kill_switch()
                
                for profile_name in profile_names:
                    if self.stop_connecting_event.is_set(): break
                    self.log(f"Probing with profile: '{profile_name}'")
                    self.create_credentials_file(complete_profiles[profile_name]["username"], complete_profiles[profile_name]["password"])
                    success, reason = self.connect_to_vpn(config_path, protocol)
                    if success: connection_successful = True; break
                    elif "auth" in reason.lower(): self.log(f"Auth failed with '{profile_name}'.", "WARNING"); continue
                    else: self.log(f"Connection failed: {reason}. Stopping probe for this server.", "ERROR"); break
                if connection_successful: break
            if not connection_successful: self.log("All connection attempts failed.", "ERROR"); self.root.after(0, self.reset_ui_to_disconnected)
        except Exception as e: self.log(f"Connection procedure failed: {e}", "CRITICAL"); self.root.after(0, self.reset_ui_to_disconnected)

    def cleanup(self):
        if os.path.exists(VPN_CONFIG_DIR): shutil.rmtree(VPN_CONFIG_DIR, ignore_errors=True)
        os.makedirs(VPN_CONFIG_DIR, exist_ok=True); self.log("Old temp files removed.")

    def download_vpn_configs(self):
        if not self.settings.get("vpn_zip_links"): self.log("No VPN ZIP links configured.", "INFO"); return
        self.log("Downloading VPN configurations...")
        for zip_link in self.settings.get("vpn_zip_links", []):
            if "drive.google.com" in zip_link: self._download_gdrive_file(zip_link, VPN_CONFIG_DIR)
            else:
                try:
                    with requests.get(zip_link, stream=True, verify=False, timeout=15) as r:
                        r.raise_for_status(); filename = os.path.basename(zip_link)
                        file_path = os.path.join(VPN_CONFIG_DIR, filename)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        with open(file_path, "wb") as f:
                            for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
                        self.log(f"Downloaded: {filename}")
                except Exception as e: self.log(f"Download failed for {zip_link}: {e}", "ERROR")

    def _download_gdrive_file(self, url, destination_folder):
        try:
            self.log(f"Processing Google Drive link..."); session = requests.Session(); response = session.get(url, stream=True, timeout=15, verify=False)
            token = next((v for k, v in response.cookies.items() if k.startswith('download_warning')), None)
            if token: url += '&confirm=' + token; response = session.get(url, stream=True, timeout=15, verify=False)
            filename = "gdrive_download.zip"
            if (cd := response.headers.get('content-disposition')) and (found := re.findall('filename="(.+)"', cd)): filename = found[0]
            file_path = os.path.join(destination_folder, filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192): f.write(chunk)
            self.log(f"Downloaded from GDrive: {filename}", "SUCCESS")
        except Exception as e: self.log(f"GDrive download failed: {e}", "ERROR")

    def extract_zip_files(self):
        self.log("Extracting .zip files...")
        zip_files = glob.glob(os.path.join(VPN_CONFIG_DIR, "*.zip"))
        if not zip_files: self.log("No .zip files to extract.", "INFO"); return
        for zip_path in zip_files:
            try:
                with zipfile.ZipFile(zip_path, 'r') as zr: zr.extractall(VPN_CONFIG_DIR)
                self.log(f"Extracted {os.path.basename(zip_path)}")
            except zipfile.BadZipFile: self.log(f"Corrupt ZIP file: {zip_path}", "ERROR")

    def _process_ovpn_file(self, ovpn_path):
        try:
            with open(ovpn_path, "r+", encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if PLATFORM != 'linux':
                    content, num_subs = re.subn(r'^\s*(up|down)\s+.*$', r'# \g<0>', content, flags=re.MULTILINE)
                    if num_subs > 0: self.log(f"Sanitized {os.path.basename(ovpn_path)} for non-Linux.")
                content = re.sub(r'^\s*dhcp-option DNS .*\n?', '', content, flags=re.MULTILINE)
                content = re.sub(r'^\s*proto\s+(udp|tcp)\s*$', '', content, flags=re.MULTILINE | re.IGNORECASE)
                content = re.sub(r'^\s*auth-user-pass.*$', 'auth-user-pass auth.txt', content, flags=re.MULTILINE | re.IGNORECASE)
                if 'auth-user-pass' not in content: content += '\nauth-user-pass auth.txt'
                dns_options = "\n".join([f"dhcp-option DNS {dns}" for dns in self.settings.get("custom_dns", [])])
                content += f"\n{dns_options}\n"
                f.seek(0); f.write(content); f.truncate()
                friendly_name = os.path.basename(ovpn_path).replace('.ovpn', '').strip()
                self.vpn_servers[friendly_name] = ovpn_path
        except Exception as e: self.log(f"Failed to process {ovpn_path}: {e}", "ERROR")

    def load_all_ovpn_configs(self):
        self.log("Loading and processing .ovpn files..."); self.vpn_servers = {}
        config_paths = glob.glob(os.path.join(VPN_CONFIG_DIR, "**", "*.ovpn"), recursive=True) + glob.glob(os.path.join(CUSTOM_CONFIG_DIR, "*.ovpn"))
        for ovpn_path in config_paths: self._process_ovpn_file(ovpn_path)
        self.log(f"Found {len(self.vpn_servers)} server configurations.")

    def update_server_list_from_filter(self, *args):
        filt = self.filter_var.get().lower(); all_server_names = list(self.vpn_servers.keys())
        favs = [s for s in all_server_names if s in self.favorites and filt in s.lower()]
        others = [s for s in all_server_names if s not in self.favorites and filt in s.lower()]
        server_names = ["Auto (Best Performance)"] + sorted(favs) + sorted(others)
        self.server_menu['values'] = server_names; current_selection = self.server_var.get()
        if current_selection not in server_names: self.server_var.set(server_names[0] if server_names else "")
        self.server_menu.config(state='readonly')

    def toggle_favorite(self):
        server = self.server_var.get()
        if server and "Auto" not in server:
            if server in self.favorites: self.favorites.remove(server)
            else: self.favorites.add(server)
            self.save_settings(); self.update_server_list_from_filter()

    def create_credentials_file(self, username, password):
        file_path = os.path.join(VPN_CONFIG_DIR, "auth.txt")
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w") as f: f.write(f"{username}\n{password}")
            if PLATFORM != 'windows': os.chmod(file_path, 0o600)
        except Exception as e: self.log(f"Failed to create credentials file {file_path}: {e}", "ERROR")

    def _infer_protocol_from_filename(self, filename):
        name_lower = filename.lower(); return 'tcp' if 'tcp' in name_lower else 'udp'

    def find_best_servers(self, limit=None):
        if not self.vpn_servers: return []
        
        servers_to_test = self.vpn_servers
        if limit:
            self.log(f"Testing a random sample of {limit} servers for speed...")
            if len(self.vpn_servers) > limit:
                server_items = list(self.vpn_servers.items())
                random.shuffle(server_items)
                servers_to_test = dict(server_items[:limit])
        else:
            self.log(f"Testing all {len(self.vpn_servers)} servers...")

        results, threads, result_queue = [], [], queue.Queue()
        def test_server(name, config_path):
            if self.stop_connecting_event.is_set(): return
            latency = self._ping_latency(config_path)
            if latency < float('inf'): result_queue.put((latency, config_path, name))
        
        for name, config_path in servers_to_test.items():
            if self.stop_connecting_event.is_set(): break
            thread = threading.Thread(target=test_server, args=(name, config_path)); threads.append(thread); thread.start()
        for thread in threads: thread.join(timeout=11)
        
        while not result_queue.empty(): results.append(result_queue.get())
        
        results.sort(key=lambda x: x[0])
        return [(path, name, self._infer_protocol_from_filename(name)) for _, path, name in results]

    def _ping_latency(self, ovpn_path):
        server_address = None
        try:
            with open(ovpn_path, 'r', encoding='utf-8', errors='ignore') as f:
                if match := re.search(r'^\s*remote\s+([^\s]+)', f.read(), re.MULTILINE): server_address = match.group(1)
        except Exception: return float('inf')
        if not server_address: return float('inf')
        try:
            result = subprocess.run(PLATFORM_CONFIG['ping_cmd'] + [server_address], capture_output=True, text=True, timeout=10, creationflags=PLATFORM_CONFIG['creationflags'])
            if match := re.search(PLATFORM_CONFIG['ping_pattern'], result.stdout): return float(match.group(1))
        except Exception as e: self.log(f"Ping failed for {server_address}: {e}", "WARNING")
        return float('inf')

    def get_server_address_from_config(self, config_path):
        if not config_path: return None, None
        try:
            with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if match := re.search(r'^\s*remote\s+([^\s]+)\s+(\d+)', content, re.MULTILINE):
                    return match.group(1), match.group(2)
                if match := re.search(r'^\s*remote\s+([^\s]+)', content, re.MULTILINE):
                    return match.group(1), None
        except:
            pass
        return None, None

    def connect_to_vpn(self, vpn_config, protocol):
        self.log(f"Starting OpenVPN for {os.path.basename(vpn_config)} with {protocol.upper()}..."); status_queue = queue.Queue()
        try:
            if not self.openvpn_executable_path: raise FileNotFoundError("OpenVPN path not set.")
            temp_config = os.path.join(tempfile.gettempdir(), "temp.ovpn")
            shutil.copy(vpn_config, temp_config)
            with open(temp_config, "a") as f:
                if self.settings["split_tunnel_mode"] == "include" or self.settings["app_split_mode"] == "include":
                    f.write("\npull-filter ignore 'redirect-gateway'\n")
            command = PLATFORM_CONFIG['sudo_prefix'] + [ self.openvpn_executable_path, "--config", temp_config, "--proto", protocol, "--auth-user-pass", os.path.join(VPN_CONFIG_DIR, "auth.txt") ]
            self.vpn_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True, creationflags=PLATFORM_CONFIG['creationflags'], encoding='utf-8', errors='replace')
            monitor_thread = threading.Thread(target=self.monitor_connection_state, args=(status_queue,), daemon=True); monitor_thread.start()
            try:
                status, reason = status_queue.get(timeout=45)
                if status == 'SUCCESS': return True, reason
                else:
                    if self.vpn_process:
                        try: self.vpn_process.kill()
                        except: pass
                    return False, reason
            except queue.Empty:
                if not self.stop_connecting_event.is_set(): self.log("Connection timed out.", "ERROR")
                if self.vpn_process:
                    try: self.vpn_process.kill()
                    except: pass
                return False, "Connection timed out."
        except Exception as e: self.log(f"Failed to start OpenVPN: {e}", "CRITICAL"); self.root.after(0, self.reset_ui_to_disconnected); return False, str(e)

    def monitor_connection_state(self, status_queue):
        failure_keywords = { "AUTH_FAILED": "Authentication failed", "auth-failure": "Authentication failed", "TLS Error": "TLS handshake failed", "Cannot resolve host address": "DNS resolution failed", "ERROR:": "Critical OpenVPN error" }
        for line in iter(self.vpn_process.stdout.readline, ''):
            if self.stop_connecting_event.is_set(): status_queue.put(('FAILURE', 'Cancelled by user.')); return
            stripped_line = line.strip(); self.log(f"OpenVPN: {stripped_line}")
            if "Initialization Sequence Completed" in stripped_line: self.root.after(0, self.update_status_connected); status_queue.put(('SUCCESS', 'Connection established.')); return
            for keyword, message in failure_keywords.items():
                if keyword in stripped_line: status_queue.put(('FAILURE', message)); return
        if not self.is_connected and not self.stop_connecting_event.is_set(): status_queue.put(('FAILURE', 'OpenVPN process exited unexpectedly.'))

    def update_status_connected(self):
        self.is_connected, self.is_connecting = True, False
        if psutil and hasattr(self, 'up_interfaces_before_connect'):
            time.sleep(3) # Give the OS a moment to fully bring up the interface and its stats
            after_up = {name for name, stats in psutil.net_if_stats().items() if stats.isup}
            newly_up = after_up - self.up_interfaces_before_connect
            if newly_up:
                self.vpn_interface_name = newly_up.pop()
                self.log(f"Detected newly active VPN interface: '{self.vpn_interface_name}'", "SUCCESS")
            else:
                self.vpn_interface_name = None
                self.log("Could not detect a newly activated VPN interface. Bandwidth monitor may not work.", "WARNING")
        
        self.vpn_gateway = self.get_vpn_gateway()
        self.apply_split_tunnel_routes()
        self.setup_app_split_tunneling()
        
        if self.settings["kill_switch"] and PLATFORM == "linux":
            self.enable_kill_switch()

        if self.app_split_setup and PLATFORM == 'linux' and self.settings.get("app_split_mode", "off") != "off":
            self.populate_split_apps_frame()
            self.split_apps_frame.pack(after=self.status_label.master, fill=tk.X, pady=5)

        self.log("Connection Established!", "SUCCESS"); self.status_label.config(text="Status: Connected", foreground="#6a8759")
        self.disconnect_button.config(state=tk.NORMAL); self.stop_button.config(state=tk.DISABLED); self.server_menu.config(state=tk.DISABLED); self.refresh_ip_button.config(state=tk.NORMAL)
        threading.Thread(target=self.update_public_ip, daemon=True).start()
        self.stop_bw_monitor.clear(); threading.Thread(target=self.bandwidth_monitor_thread, daemon=True).start()
        threading.Thread(target=self.monitor_vpn_process, daemon=True).start()

    def monitor_vpn_process(self):
        while self.is_connected and not self.stop_connecting_event.is_set():
            if self.vpn_process.poll() is not None:
                self.log("VPN connection dropped unexpectedly.", "WARNING")
                self.disconnect_vpn()
                if self.settings["auto_reconnect"]:
                    self.log("Attempting auto-reconnect...", "INFO")
                    self.start_vpn_thread()
                break
            time.sleep(5)

    def setup_app_split_tunneling(self):
        if PLATFORM != 'linux' or self.settings.get("app_split_mode", "off") == "off":
            return
        
        self.log("Setting up App Split Tunneling using Network Namespace...", "INFO")
        mode = self.settings["app_split_mode"]
        ns_name = "appsplit_ns"
        veth_host = "veth-host"; veth_ns = "veth-ns"
        veth_host_ip = "192.168.200.1"; veth_ns_ip = "192.168.200.2"; subnet = "24"
        rt_table_name = "appsplit_rt"; rt_table_id = "100"
        
        try:
            self.cleanup_app_split_tunneling()
            subprocess.run(["sudo", "ip", "netns", "add", ns_name], check=True)
            subprocess.run(["sudo", "ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_ns], check=True)
            subprocess.run(["sudo", "ip", "link", "set", veth_ns, "netns", ns_name], check=True)
            subprocess.run(["sudo", "ip", "addr", "add", f"{veth_host_ip}/{subnet}", "dev", veth_host], check=True)
            subprocess.run(["sudo", "ip", "link", "set", veth_host, "up"], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", ns_name, "ip", "addr", "add", f"{veth_ns_ip}/{subnet}", "dev", veth_ns], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "set", veth_ns, "up"], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", ns_name, "ip", "route", "add", "default", "via", veth_host_ip], check=True)
            
            subprocess.run(["sudo", "mkdir", "-p", f"/etc/netns/{ns_name}"], check=True)
            resolv_content = "nameserver 8.8.8.8\\nnameserver 8.8.4.4\\n"
            subprocess.run(f'echo "{resolv_content}" | sudo tee /etc/netns/{ns_name}/resolv.conf > /dev/null', shell=True, check=True)
            
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            
            if mode == "exclude":
                if not self.original_iface or not self.original_gateway:
                    raise ValueError("Original network interface or gateway not found for exclude mode.")
                
                rt_tables_path = "/etc/iproute2/rt_tables"
                rt_table_entry = f"{rt_table_id} {rt_table_name}"
                update_cmd = (
                    f"grep -qxF '{rt_table_entry}' {rt_tables_path} 2>/dev/null || "
                    f"echo '{rt_table_entry}' | sudo tee -a {rt_tables_path} > /dev/null"
                )
                subprocess.run(update_cmd, shell=True, check=True)

                subprocess.run(["sudo", "ip", "route", "add", "default", "via", self.original_gateway, "dev", self.original_iface, "table", rt_table_name], check=True)
                subprocess.run(["sudo", "ip", "rule", "add", "from", f"{veth_ns_ip}/32", "lookup", rt_table_name], check=True)
                subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"{veth_ns_ip}/32", "-o", self.original_iface, "-j", "MASQUERADE"], check=True)

                subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", self.original_iface, "-o", veth_host, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=True)
                subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", veth_host, "-o", self.original_iface, "-j", "ACCEPT"], check=True)
            
            elif mode == "include":
                if not self.vpn_interface_name:
                    raise ValueError("VPN network interface not found for include mode.")
                subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"{veth_ns_ip}/32", "-o", self.vpn_interface_name, "-j", "MASQUERADE"], check=True)

            self.app_split_setup = True
            self.log("App Split Tunneling (netns) setup complete.", "SUCCESS")

        except Exception as e:
            self.log(f"Failed to setup netns app split tunneling: {e}", "ERROR")
            self.log("App Split Tunneling will be disabled.", "WARNING")
            self.cleanup_app_split_tunneling()
            self.app_split_setup = False

    def cleanup_app_split_tunneling(self):
        if PLATFORM != 'linux':
            return
        ns_name, veth_host, veth_ns_ip, rt_table_name = "appsplit_ns", "veth-host", "192.168.200.2", "appsplit_rt"
        if self.original_iface: 
            subprocess.run(["sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"{veth_ns_ip}/32", "-o", self.original_iface, "-j", "MASQUERADE"], check=False, capture_output=True)
            subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-i", self.original_iface, "-o", veth_host, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False, capture_output=True)
            subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-i", veth_host, "-o", self.original_iface, "-j", "ACCEPT"], check=False, capture_output=True)
        if self.vpn_interface_name: subprocess.run(["sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"{veth_ns_ip}/32", "-o", self.vpn_interface_name, "-j", "MASQUERADE"], check=False, capture_output=True)
        subprocess.run(["sudo", "ip", "rule", "del", "from", f"{veth_ns_ip}/32", "lookup", rt_table_name], check=False, capture_output=True)
        subprocess.run(["sudo", "ip", "route", "flush", "table", rt_table_name], check=False, capture_output=True)
        subprocess.run(["sudo", "ip", "link", "del", veth_host], check=False, capture_output=True)
        result = subprocess.run(["sudo", "ip", "netns", "del", ns_name], check=False, capture_output=True)
        if result.returncode == 0 and self.is_connected:
            self.log("App Split Tunneling (netns) cleaned up.", "SUCCESS")
        self.app_split_setup = False

    def apply_split_tunnel_routes(self):
        mode = self.settings["split_tunnel_mode"]
        if mode == "off": return
        if not self.original_gateway or not self.vpn_gateway:
            self.log("Cannot apply split tunnel routes: Gateways not detected.", "ERROR"); return
        if mode == "exclude":
            for ip in self.settings["split_tunnel_ips"]:
                self.add_route(ip, self.original_gateway, self.original_iface if PLATFORM == "linux" else None)
        elif mode == "include":
            self.add_route("0.0.0.0/0", self.original_gateway, self.original_iface if PLATFORM == "linux" else None)
            for ip in self.settings["split_tunnel_ips"]:
                self.add_route(ip, self.vpn_gateway)

    def cidr_to_netmask(self, cidr):
        if '/' not in cidr: return cidr, "255.255.255.255"
        network, bits = cidr.split('/')
        bits = int(bits)
        mask_int = (0xffffffff << (32 - bits)) & 0xffffffff
        mask = '.'.join([str((mask_int >> (i * 8)) & 0xff) for i in range(3, -1, -1)])
        return network, mask

    def add_route(self, destination, gateway, interface=None):
        if PLATFORM in ("linux", "macos"):
            cmd = PLATFORM_CONFIG['sudo_prefix'] + ["ip", "route", "replace", destination, "via", gateway]
            if interface: cmd += ["dev", interface]
        elif PLATFORM == "windows":
            network, mask = self.cidr_to_netmask(destination)
            cmd = ["route", "add", network, "mask", mask, gateway]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            self.active_routes.append((destination, gateway, interface))
            self.log(f"Added/Replaced route {destination} via {gateway}")
        except Exception as e:
            error_output = e.stderr.decode().strip() if hasattr(e, 'stderr') and e.stderr else str(e)
            if "File exists" in error_output or "The object already exists" in error_output:
                self.log(f"Route for {destination} already exists, which is OK.", "INFO")
                self.active_routes.append((destination, gateway, interface))
            else:
                self.log(f"Failed to add route {destination}: {error_output}", "ERROR")

    def delete_route(self, destination, gateway, interface=None):
        if PLATFORM in ("linux", "macos"):
            cmd = PLATFORM_CONFIG['sudo_prefix'] + ["ip", "route", "del", destination, "via", gateway]
            if interface: cmd += ["dev", interface]
        elif PLATFORM == "windows":
            network, mask = self.cidr_to_netmask(destination)
            cmd = ["route", "delete", network, "mask", mask]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            self.log(f"Deleted route {destination} via {gateway}")
        except Exception as e:
            self.log(f"Failed to delete route {destination}: {e}", "WARNING")

    def get_default_gateway(self):
        try:
            result = subprocess.run(PLATFORM_CONFIG['get_gateway_cmd'], capture_output=True, text=True)
            if match := re.search(PLATFORM_CONFIG['gateway_pattern'], result.stdout, re.MULTILINE):
                gw = match.group(1)
                iface = match.group(2) if len(match.groups()) > 1 else None
                return gw, iface
        except Exception as e:
            self.log(f"Failed to get default gateway: {e}", "ERROR")
        return None, None

    def get_vpn_gateway(self):
        for attempt in range(1, 6):
            self.log(f"Attempting to find VPN gateway (Attempt {attempt}/5)...")
            try:
                cmd = None
                if PLATFORM == 'windows':
                    cmd = PLATFORM_CONFIG['vpn_gateway_cmd']
                elif PLATFORM == 'linux' and self.vpn_interface_name:
                    cmd = ["ip", "route", "show", "dev", self.vpn_interface_name]

                if not cmd:
                    self.log("Could not determine command to find VPN gateway.", "WARNING")
                    time.sleep(1)
                    continue

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                if PLATFORM == 'windows':
                    matches = re.finditer(PLATFORM_CONFIG['vpn_gateway_pattern'], result.stdout, re.MULTILINE)
                    for match in matches:
                        gateway_ip = match.group(1)
                        if gateway_ip != self.original_gateway:
                            self.log(f"Successfully found new VPN gateway (Method A): {gateway_ip}", "SUCCESS")
                            return gateway_ip
                    alt_pattern = r"0\.0\.0\.0\s+128\.0\.0\.0\s+([\d\.]+)"
                    if match := re.search(alt_pattern, result.stdout, re.MULTILINE):
                        gateway_ip = match.group(1)
                        self.log(f"Successfully found new VPN gateway (Method B): {gateway_ip}", "SUCCESS")
                        return gateway_ip

                else: # For Linux/macOS
                    if match := re.search(PLATFORM_CONFIG['vpn_gateway_pattern'], result.stdout, re.MULTILINE):
                        vpn_gw = match.group(1)
                        self.log(f"Successfully found VPN gateway: {vpn_gw}", "SUCCESS")
                        return vpn_gw

            except Exception as e:
                self.log(f"Error while getting VPN gateway: {e}", "ERROR")
                return None
            
            time.sleep(1)
        
        self.log(f"Failed to get VPN gateway after 5 attempts.", "ERROR")
        return None

    def enable_kill_switch(self):
        self.log("ENABLING KILL SWITCH: Applying robust firewall rules...", "WARNING")
        try:
            vpn_server_ip, vpn_server_port_str = self.get_server_address_from_config(self.active_config_path)
            vpn_protocol = self._infer_protocol_from_filename(self.active_server_name)
            vpn_server_port = vpn_server_port_str if vpn_server_port_str else ('1194' if vpn_protocol == 'udp' else '443')

            if not all([self.original_iface, vpn_server_ip, vpn_server_port, self.vpn_interface_name]):
                raise ValueError("Missing critical network details to apply kill switch.")

            subprocess.run(["sudo", "ufw", "reset"], input='y', text=True, check=True, capture_output=True)
            subprocess.run(["sudo", "ufw", "default", "deny", "outgoing"], check=True, capture_output=True)
            subprocess.run(["sudo", "ufw", "default", "deny", "incoming"], check=True, capture_output=True)
            subprocess.run(["sudo", "ufw", "allow", "out", "on", "lo"], check=True, capture_output=True)
            subprocess.run(["sudo", "ufw", "allow", "in", "on", "lo"], check=True, capture_output=True)
            for net in ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]:
                subprocess.run(["sudo", "ufw", "allow", "out", "to", net], check=True, capture_output=True)
                subprocess.run(["sudo", "ufw", "allow", "in", "from", net], check=True, capture_output=True)

            self.log(f"Kill Switch: Allowing traffic to VPN server {vpn_server_ip}:{vpn_server_port}", "INFO")
            subprocess.run([
                "sudo", "ufw", "allow", "out", "on", self.original_iface, "to", vpn_server_ip,
                "port", vpn_server_port, "proto", vpn_protocol
            ], check=True, capture_output=True)

            self.log(f"Kill Switch: Allowing all traffic on VPN interface {self.vpn_interface_name}", "INFO")
            subprocess.run(["sudo", "ufw", "allow", "out", "on", self.vpn_interface_name], check=True, capture_output=True)
            
            if self.app_split_setup and self.settings.get("app_split_mode") == "exclude":
                self.log("Kill Switch: Allowing all traffic on original interface for excluded apps.", "INFO")
                subprocess.run(["sudo", "ufw", "allow", "out", "on", self.original_iface], check=True, capture_output=True)
            else:
                self.log("Kill Switch: Applying DNS leak protection.", "INFO")
                subprocess.run(["sudo", "ufw", "deny", "out", "on", self.original_iface, "to", "any", "port", "53"], check=True, capture_output=True)
            
            subprocess.run(["sudo", "ufw", "enable"], check=True, capture_output=True)
            self.log("KILL SWITCH ENABLED: Firewall is active and secure.", "SUCCESS")

        except Exception as e:
            error_output = e.stderr.decode() if hasattr(e, 'stderr') and e.stderr else str(e)
            self.log(f"CRITICAL: FAILED TO ENABLE KILL SWITCH. Internet may be unblocked. Error: {error_output}", "CRITICAL")
            messagebox.showerror("Kill Switch Failed", f"Could not enable the firewall. Disconnecting for safety.\n\nError: {error_output}")
            self.disconnect_vpn()

    def disable_kill_switch(self):
        self.log("DISABLING KILL SWITCH: Resetting firewall rules...", "WARNING")
        try:
            subprocess.run(["sudo", "ufw", "reset"], input='y', text=True, check=False, capture_output=True)
            self.log("Kill switch disabled and firewall reset.", "SUCCESS")
        except Exception as e:
            self.log(f"Failed to cleanly disable kill switch: {e}", "ERROR")
            
    def reset_ui_to_disconnected(self):
        self.is_connected, self.is_connecting = False, False
        if self.vpn_process:
            try: self.vpn_process.kill()
            except: pass
            self.vpn_process = None
        for dest, gw, iface in self.active_routes:
            self.delete_route(dest, gw, iface)
        self.active_routes = []
        self.cleanup_app_split_tunneling()
        if self.settings["kill_switch"] and PLATFORM == "linux":
            self.disable_kill_switch()
        self.status_label.config(text="Status: Disconnected", foreground="#ff6b68"); self.ip_label.config(text="Public IP: N/A"); self.bw_label.config(text="BW: 0.0 KB/s ↓ 0.0 KB/s ↑")
        self.connect_button.config(state=tk.NORMAL); self.stop_button.config(state=tk.DISABLED); self.disconnect_button.config(state=tk.DISABLED); self.refresh_ip_button.config(state=tk.DISABLED)
        if self.vpn_servers: self.server_menu.config(state='readonly')
        self.split_apps_frame.pack_forget()
        self.stop_bw_monitor.set()

    def update_public_ip(self):
        self.root.after(0, lambda: self.ip_label.config(text="Public IP: Fetching..."))
        try:
            time.sleep(2)
            ip = requests.get("https://api.ipify.org", timeout=10).text
            self.root.after(0, lambda: self.ip_label.config(text=f"Public IP: {ip}"))
        except Exception as e: self.log(f"Failed to fetch public IP: {e}", "WARNING"); self.root.after(0, lambda: self.ip_label.config(text="Public IP: Failed"))

    def disconnect_vpn(self):
        self.log("Disconnecting..."); self.stop_connecting_event.set(); self.stop_bw_monitor.set()
        if self.vpn_process:
            try:
                if PLATFORM == 'windows': subprocess.run(["taskkill", "/PID", str(self.vpn_process.pid), "/F", "/T"], check=True, timeout=5, creationflags=PLATFORM_CONFIG['creationflags'])
                else: subprocess.run(PLATFORM_CONFIG['sudo_prefix'] + PLATFORM_CONFIG['kill_cmd'], check=False, timeout=5)
            except Exception as e:
                self.log(f"Graceful disconnect failed, forcing kill: {e}", "WARNING")
                if self.vpn_process: self.vpn_process.kill()
            self.vpn_process = None
        self.reset_ui_to_disconnected(); self.log("Disconnected successfully.", "SUCCESS")

    def on_closing(self): self.disconnect_vpn(); self.root.destroy()

    def import_ovpn_file(self):
        if self.is_connecting or self.is_connected: messagebox.showwarning("Busy", "Cannot import files while connecting."); return
        filepaths = filedialog.askopenfilenames(title="Import OpenVPN Configuration(s)", filetypes=[("OpenVPN files", "*.ovpn"), ("All files", "*.*")])
        if not filepaths: return
        imported_count = 0
        for filepath in filepaths:
            filename = os.path.basename(filepath); dest_path = os.path.join(CUSTOM_CONFIG_DIR, filename)
            try:
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                if os.path.exists(dest_path) and not messagebox.askyesno("Overwrite?", f"Configuration '{filename}' already exists. Overwrite?"): continue
                shutil.copy(filepath, dest_path); self._process_ovpn_file(dest_path); imported_count += 1
            except Exception as e: self.log(f"Failed to import {filename}: {e}", "ERROR")
        if imported_count > 0: self.load_all_ovpn_configs(); self.update_server_list_from_filter(); messagebox.showinfo("Success", f"Successfully imported {imported_count} file(s).")

    def bandwidth_monitor_thread(self):
        if not psutil or not self.vpn_interface_name:
            self.log("Bandwidth monitor cannot start: psutil not loaded or VPN interface not detected.", "WARNING")
            return

        self.log(f"Starting bandwidth monitor on '{self.vpn_interface_name}'.")
        try:
            counters = psutil.net_io_counters(pernic=True)
            last_bytes_sent = counters[self.vpn_interface_name].bytes_sent
            last_bytes_recv = counters[self.vpn_interface_name].bytes_recv
        except KeyError:
            self.log(f"Initial bandwidth read failed for interface '{self.vpn_interface_name}'.", "WARNING")
            return

        while not self.stop_bw_monitor.wait(2):
            try:
                counters = psutil.net_io_counters(pernic=True)
                if self.vpn_interface_name not in counters:
                    self.log(f"VPN interface '{self.vpn_interface_name}' disappeared.", "WARNING")
                    break
                bytes_sent = counters[self.vpn_interface_name].bytes_sent
                bytes_recv = counters[self.vpn_interface_name].bytes_recv
                sent_speed = (bytes_sent - last_bytes_sent) / 2 / 1024
                recv_speed = (bytes_recv - last_bytes_recv) / 2 / 1024
                last_bytes_sent, last_bytes_recv = bytes_sent, bytes_recv
                bw_text = f"BW: {recv_speed:.1f} KB/s ↓ {sent_speed:.1f} KB/s ↑"
                self.root.after(0, lambda s=bw_text: self.bw_label.config(text=s))
            except (KeyError, psutil.NoSuchProcess):
                break
        self.log("Bandwidth monitor stopped.")

def check_and_install_dependencies():
    required_pip_packages = {'requests': requests, 'psutil': psutil}
    missing_packages = [pkg for pkg, lib in required_pip_packages.items() if lib is None]
    if missing_packages:
        package_str = ", ".join(missing_packages)
        if messagebox.askyesno("Dependencies Missing", f"The following required libraries are missing: {package_str}.\n\nAttempt automatic installation?"):
            try:
                if 'psutil' in missing_packages and PLATFORM == 'linux' and shutil.which('apt-get'):
                    logging.info("Attempting to install python3-psutil via apt-get...")
                    subprocess.run(["sudo", "apt-get", "update"], check=True)
                    subprocess.run(["sudo", "apt-get", "install", "python3-psutil", "-y"], check=True)
                    missing_packages.remove('psutil')
                
                if missing_packages:
                    pip_cmd = [sys.executable, "-m", "pip", "install"] + missing_packages
                    logging.info(f"Running pip to install: {' '.join(pip_cmd)}")
                    subprocess.run(pip_cmd, check=True)
                
                messagebox.showinfo("Installation Complete", "Dependencies have been installed. Please restart the application.")
            except Exception as e:
                messagebox.showerror("Installation Failed", f"Failed to install libraries. Please install them manually.\n\nError: {e}\n\nCommand: `pip install {' '.join(missing_packages)}`")
        return False
    
    openvpn_path = shutil.which('openvpn')
    if not openvpn_path and PLATFORM == 'windows':
        for path in [r"C:\Program Files\OpenVPN\bin\openvpn.exe", r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe"]:
            if os.path.exists(path):
                openvpn_path = path
                break
    
    if not openvpn_path:
        if not messagebox.askyesno("OpenVPN Not Found", "The OpenVPN client is not installed or not in your system's PATH.\n\nWould you like to attempt an automatic installation?"):
            return False
        install_success = False
        try:
            if PLATFORM == 'windows': install_success = install_openvpn_windows()
            elif PLATFORM == 'linux': install_success = install_openvpn_linux()
            elif PLATFORM == 'macos': install_success = install_openvpn_macos()
        except Exception as e:
            logging.error(f"An unexpected error occurred during OpenVPN installation: {e}")
            messagebox.showerror("Installation Error", f"An unexpected error occurred: {e}")
        if install_success:
            messagebox.showinfo("Installation Complete", "OpenVPN has been installed. Please restart the application for the changes to take effect.")
        return False

    if PLATFORM == 'linux' and not shutil.which('ufw'):
        temp_settings = {}
        try:
            with open(CONFIG_FILE, 'r') as f: temp_settings = json.load(f)
        except: pass
        
        if temp_settings.get("kill_switch", False):
            if messagebox.askyesno("Dependency Missing", "The 'ufw' firewall is required for the Kill Switch on Linux but is not found.\n\nWould you like to attempt to install it now?"):
                try:
                    logging.info("Attempting to install ufw via apt-get...")
                    subprocess.run(["sudo", "apt-get", "update"], check=True)
                    subprocess.run(["sudo", "apt-get", "install", "ufw", "-y"], check=True)
                    messagebox.showinfo("Installation Complete", "'ufw' has been installed. Please restart the application.")
                except Exception as e:
                    messagebox.showerror("Installation Failed", f"Failed to install 'ufw'. Please install it manually using your system's package manager.\n\nError: {e}")
            return False

    logging.info("All dependencies are met.")
    return True

def install_openvpn_windows():
    logging.info("Attempting to install OpenVPN on Windows...")
    installer_path = os.path.join(tempfile.gettempdir(), "OpenVPN-Installer.msi")
    try:
        logging.info(f"Downloading OpenVPN installer from {OPENVPN_WINDOWS_INSTALLER_URL}")
        with requests.get(OPENVPN_WINDOWS_INSTALLER_URL, stream=True) as r:
            r.raise_for_status()
            with open(installer_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        
        logging.info("Download complete. Running MSI installer silently...")
        subprocess.run(['msiexec', '/i', installer_path, '/passive'], check=True)
        logging.info("OpenVPN installation command executed.")
        return True
    except Exception as e:
        logging.error(f"Windows OpenVPN installation failed: {e}")
        messagebox.showerror("Installation Failed", f"Failed to download or run the OpenVPN installer: {e}")
        return False
    finally:
        if os.path.exists(installer_path):
            os.remove(installer_path)

def install_openvpn_linux():
    logging.info("Attempting to install OpenVPN on Linux...")
    package_managers = { 'apt-get': ["sudo", "apt-get", "update", "-y"], 'dnf': ["sudo", "dnf", "check-update"], 'yum': ["sudo", "yum", "check-update"], 'pacman': ["sudo", "pacman", "-Sy"] }
    install_commands = { 'apt-get': ["sudo", "apt-get", "install", "openvpn", "-y"], 'dnf': ["sudo", "dnf", "install", "openvpn", "-y"], 'yum': ["sudo", "yum", "install", "openvpn", "-y"], 'pacman': ["sudo", "pacman", "-S", "openvpn", "--noconfirm"] }
    for pm, update_cmd in package_managers.items():
        if shutil.which(pm):
            try:
                logging.info(f"Found package manager: {pm}. Updating repositories...")
                subprocess.run(update_cmd, check=True)
                logging.info(f"Installing OpenVPN using {pm}...")
                subprocess.run(install_commands[pm], check=True)
                logging.info("OpenVPN installed successfully via package manager.")
                return True
            except Exception as e:
                logging.error(f"Installation with {pm} failed: {e}")
                messagebox.showerror("Installation Failed", f"Installation with '{pm}' failed: {e}\nPlease install OpenVPN manually.")
                return False
    messagebox.showwarning("Installation Failed", "Could not find a supported package manager (apt, dnf, yum, pacman). Please install OpenVPN manually.")
    return False

def install_openvpn_macos():
    logging.info("Attempting to install OpenVPN on macOS via Homebrew...")
    if not shutil.which('brew'):
        messagebox.showerror("Homebrew Not Found", "Homebrew is required to auto-install OpenVPN on macOS.\n\nPlease install it from brew.sh and try again.")
        return False
    try:
        logging.info("Updating Homebrew...")
        subprocess.run(["brew", "update"], check=True)
        logging.info("Installing OpenVPN via Homebrew...")
        subprocess.run(["brew", "install", "openvpn"], check=True)
        logging.info("OpenVPN successfully installed via Homebrew.")
        return True
    except Exception as e:
        logging.error(f"Homebrew installation failed: {e}")
        messagebox.showerror("Installation Failed", f"Installation with Homebrew failed: {e}\nPlease install OpenVPN manually.")
        return False

def main():
    root = tk.Tk()
    root.withdraw()
    
    if not is_admin():
        messagebox.showerror("Admin Rights Required", "This application requires administrator (or sudo) rights to manage network settings and install dependencies. Please run it again as an administrator.")
        return
    
    if not check_and_install_dependencies():
        return
    
    openvpn_path = shutil.which('openvpn') or next((p for p in [r"C:\Program Files\OpenVPN\bin\openvpn.exe", r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe"] if PLATFORM == 'windows' and os.path.exists(p)), None)
    
    if not openvpn_path:
        messagebox.showerror("Fatal Error", "OpenVPN is still not found after an installation attempt. Please check your system's PATH or install it manually.")
        return
        
    root.deiconify()  
    app = VPNConnectorApp(root, openvpn_path)
    root.mainloop()

if __name__ == "__main__":
    main()