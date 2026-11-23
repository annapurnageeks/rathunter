"""A pretend Mac with a pretend infection, for tests and for the sample report.

Nothing here runs. The "RAT" is a text file containing the kinds of strings a real one would,
so rathunter's checks have something to find. The system commands are canned outputs.
"""

import json
import sqlite3
from pathlib import Path

import rathunter

RAT_SCRIPT = '''#!/usr/bin/env python3
# looks like a typical hobby RAT: remote control over a Telegram bot
import telebot, subprocess, os
from pynput import keyboard
bot = telebot.TeleBot(os.environ.get("T", ""))
API = "https://api.telegram.org/bot"
def shot(): subprocess.run(["screencapture", "-x", "/tmp/s.png"])
'''


def plist(path, data):
    import plistlib
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        plistlib.dump(data, f)


class SimulatedMac(rathunter.Mac):
    """A Mac whose files live in a temp folder and whose commands return canned output."""

    def __init__(self, folder, infected=True):
        folder = Path(folder)
        super().__init__(home=folder / "Users/sam", root=folder)
        self.outputs = {}
        build(self, infected)

    def run(self, *command):
        return self.outputs.get(command, "")

    def signature(self, path):
        path = str(path)
        if path.startswith("/usr/") or path.startswith("/bin/") or path.startswith("/System/"):
            return ("apple", "Apple")
        if "Zoom" in path or "Google" in path:
            return ("developer", "Zoom Video Communications" if "Zoom" in path else "Google LLC")
        return ("unsigned", None)


def build(mac, infected):
    home, root = mac.home, mac.root
    home.mkdir(parents=True)

    # A legit startup item, signed by a known developer
    plist(root / "Library/LaunchAgents/com.google.keystone.agent.plist",
          {"Label": "com.google.keystone.agent",
           "ProgramArguments": ["/Library/Application Support/Google/GoogleSoftwareUpdate/Agent"]})
    (root / "etc").mkdir(parents=True)
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n255.255.255.255 broadcasthost\n::1 localhost\n")
    mac.outputs[("csrutil", "status")] = "System Integrity Protection status: enabled."
    mac.outputs[("spctl", "--status")] = "assessments enabled"
    mac.outputs[("fdesetup", "status")] = "FileVault is On."
    mac.outputs[("ps", "-axww", "-o", "pid=,user=,comm=")] = (
        "  1 root /sbin/launchd\n 400 sam /Applications/zoom.us.app/Contents/MacOS/zoom.us\n")
    mac.outputs[("ps", "-axww", "-o", "pid=,args=")] = (
        "  1 /sbin/launchd\n 400 /Applications/zoom.us.app/Contents/MacOS/zoom.us\n")
    mac.outputs[("ps", "-axo", "comm=")] = "/sbin/launchd\n/Applications/zoom.us.app/Contents/MacOS/zoom.us\n"
    tcc = [("kTCCServiceScreenCapture", "us.zoom.xos", 0, 2), ("kTCCServiceMicrophone", "us.zoom.xos", 0, 2),
           ("kTCCServiceCamera", "us.zoom.xos", 0, 2)]

    if infected:
        hidden = home / ".local-sync"
        hidden.mkdir()
        rat = hidden / "agent.py"
        rat.write_text(RAT_SCRIPT)
        # 1. persistence, disguised as an Apple item
        plist(home / "Library/LaunchAgents/com.apple.softwareupdate.helper.plist",
              {"Label": "com.apple.softwareupdate.helper", "ProgramArguments": ["/usr/bin/python3", str(rat)],
               "RunAtLoad": True, "KeepAlive": True})
        # 2. a terminal startup file that captures your sudo password
        (home / ".zshrc").write_text("export PATH=$PATH:/opt/homebrew/bin\n"
                                     "alias sudo='$HOME/.local-sync/s.sh'\n")
        # 3. it can read your keyboard
        tcc.append(("kTCCServiceListenEvent", str(rat), 1, 2))
        # 4. it's running and talking to Telegram
        mac.outputs[("ps", "-axww", "-o", "pid=,user=,comm=")] += " 4242 sam /usr/bin/python3\n 4300 sam /private/tmp/.x/kernel_task\n"
        mac.outputs[("ps", "-axww", "-o", "pid=,args=")] += f" 4242 /usr/bin/python3 {rat}\n 4300 /private/tmp/.x/kernel_task\n"
        mac.outputs[("netstat", "-anv", "-p", "tcp")] = (
            "Active Internet connections (including servers)\n"
            "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid\n"
            "tcp4       0      0  192.168.1.20.50123     149.154.167.220.443    ESTABLISHED        13584        13641  131072  132432 python3:4242   00102\n"
            "tcp4       0      0  *.22                   *.*                    LISTEN                 0            0  131072  131072 launchd:1      00100\n")
        (home / ".ssh").mkdir()
        (home / ".ssh/authorized_keys").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey support@remote-helpdesk\n")
        # 5. someone can read the traffic
        mac.outputs[("profiles", "list")] = ("sam[1] attribute: profileIdentifier: com.apple.ManagedSettings.macOS.1\n"
                                            "sam[2] attribute: profileIdentifier: net.securewifi.config.4471\n")
        mac.outputs[("security", "dump-trust-settings")] = "Number of trusted certs = 1\nCert 0: SecureWiFi Root CA\n"
        mac.outputs[("scutil", "--proxy")] = "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 45.12.8.3\n  HTTPPort : 8080\n}"
        (root / "etc/hosts").write_text((root / "etc/hosts").read_text() +
                                        "185.22.1.9 www.paypal.com\n0.0.0.0 www.virustotal.com\n")
        # 6. a sideloaded browser extension that can read every site
        ext = home / "Library/Application Support/Google/Chrome/Default/Extensions/abcdefgh/1.0"
        ext.mkdir(parents=True)
        (ext / "manifest.json").write_text(json.dumps({
            "name": "PDF Converter Pro", "manifest_version": 3,
            "permissions": ["cookies", "webRequest", "tabs"], "host_permissions": ["<all_urls>"]}))
        # 7. a remote-control app
        (root / "Applications/AnyDesk.app").mkdir(parents=True)
        mac.outputs[("ps", "-axo", "comm=")] += "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk\n"
        mac.outputs[("csrutil", "status")] = "System Integrity Protection status: disabled."

    db = home / "Library/Application Support/com.apple.TCC/TCC.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER)")
    connection.executemany("INSERT INTO access VALUES (?, ?, ?, ?)", tcc)
    connection.commit()
    connection.close()
