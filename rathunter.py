#!/usr/bin/env python3
"""
rathunter: is someone spying on your Mac? Find RATs, stalkerware and spyware, explained in plain English.

Usage:
    python3 rathunter.py                    # scan this Mac, print what needs your attention
    python3 rathunter.py --all              # ...and also everything that looked fine
    python3 rathunter.py --html report.html --open   # a visual report you can read (and share)
    python3 rathunter.py --json             # machine-readable results

What it looks at, the way an incident responder would:
    1. What starts by itself     launch agents and daemons, login hooks, cron jobs, shell startup files
    2. What can watch you        apps allowed to see your screen, read your keyboard, use the camera or mic
    3. What can reach in         remote login, screen sharing, remote-control apps, SSH keys, listening ports
    4. What is running now       processes hiding in temporary or hidden folders, fake system processes,
                                 scripts talking to Telegram or Discord (how most hobby RATs are controlled)
    5. Who can read your traffic configuration profiles, trusted root certificates, proxies, the hosts file
    6. Browser extensions        sideloaded extensions and ones that can read every website
    7. Your defenses             System Integrity Protection, Gatekeeper, FileVault, firewall

rathunter only reads. It never changes, deletes or uploads anything, and it makes no network requests.
Only the Python standard library is used: nothing to install.
"""

import argparse
import html
import ipaddress
import json
import os
import platform
import plistlib
import re
import sqlite3
import subprocess
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

VERSION = "0.1.0"
PROJECT_URL = "https://github.com/annapurnageeks/rathunter"

DANGER, WARNING, INFO = "danger", "warning", "info"
RANK = {DANGER: 0, WARNING: 1, INFO: 2}
CATEGORIES = ["Running now", "Starts automatically", "Can watch you", "Can reach in", "Can read your traffic",
              "Browser extensions", "Your defenses"]

# Programs that run scripts. A launch agent that starts one of these is running a script, not an app.
INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "bash", "sh", "zsh", "dash", "osascript",
                "node", "php", "tclsh", "pwsh", "env"}

# Places real apps don't live. Malware likes them because nobody looks there.
SHADY_PLACES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/")

# Package managers build their own binaries, which are signed "ad-hoc". That's normal.
PACKAGE_MANAGERS = ("/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/", "/opt/local/", "/nix/store/")

# Things found inside scripts that point to remote control or spying. (label, regex)
RAT_SIGNS = [
    ("is controlled through a Telegram bot", r"api\.telegram\.org|telebot|telegram\.ext|TeleBot\("),
    ("sends data to a Discord webhook", r"discord(?:app)?\.com/api/webhooks"),
    ("opens a reverse shell", r"/dev/tcp/|\bnc\b[^\n]*\s-e\s|\bncat\b[^\n]*\s-e\s|pty\.spawn\(|"
                              r"socket\.socket\([^\n]*\)[^\n]*\n[^\n]*\.connect\("),
    ("records keystrokes", r"pynput|keyboard\.on_press|CGEventTapCreate|kCGEventKeyDown|addGlobalMonitorForEvents"),
    ("takes screenshots", r"\bscreencapture\b|ImageGrab|\bmss\(|CGWindowListCreateImage"),
    ("uses the webcam", r"\bimagesnap\b|cv2\.VideoCapture|AVCaptureDevice"),
    ("records the microphone", r"sounddevice|pyaudio|AVAudioRecorder"),
    ("steals saved passwords or keys", r"Login Data|find-generic-password|find-internet-password|\.ssh/id_|"
                                       r"Cookies\.binarycookies|login\.keychain"),
    ("downloads and runs code", r"(?:curl|wget)[^|\n]*\|\s*(?:ba|z)?sh\b|base64\s+(?:-d|-D|--decode)[^\n]*\|\s*(?:ba|z)?sh|"
                                r"exec\([^\n]*b64decode|eval\([^\n]*b64decode|exec\(\s*urllib|exec\(\s*requests\.get"),
    ("installs itself to start at login", r"Library/LaunchAgents|Library/LaunchDaemons|crontab\s"),
]

# Telegram's published server ranges (core.telegram.org/resources/cidr.txt). A script talking to these
# is the signature of the Python RATs you find on GitHub.
TELEGRAM_NETWORKS = [ipaddress.ip_network(n) for n in (
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
    "91.108.56.0/22", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24",
    "2001:b28:f23c::/48", "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48")]

# Remote-control apps. Fine if you installed them; a problem if you didn't.
REMOTE_APPS = ["TeamViewer", "AnyDesk", "RustDesk", "Splashtop", "LogMeIn", "GoToMyPC", "ScreenConnect",
               "ConnectWise", "Chrome Remote Desktop", "UltraViewer", "Ammyy", "RemotePC", "Zoho Assist",
               "NoMachine", "Parsec", "DWService", "Remote Utilities", "TightVNC", "RealVNC", "VNC Server"]

# Ports that mean someone can get into this Mac from the network.
REMOTE_PORTS = {22: "Remote Login (SSH)", 5900: "Screen Sharing (VNC)", 3283: "Apple Remote Desktop",
                445: "File Sharing (SMB)", 3389: "Remote Desktop (RDP)"}

# Privacy permissions worth knowing about, from macOS's TCC database.
PRIVACY = {
    "kTCCServiceListenEvent": ("Input Monitoring", "can read every key you type", WARNING),
    "kTCCServiceScreenCapture": ("Screen Recording", "can see everything on your screen", WARNING),
    "kTCCServiceAccessibility": ("Accessibility", "can control your Mac: click, type and read other apps", WARNING),
    "kTCCServicePostEvent": ("Keyboard & mouse control", "can type and click for you", WARNING),
    "kTCCServiceCamera": ("Camera", "can turn on your camera", INFO),
    "kTCCServiceMicrophone": ("Microphone", "can listen through your microphone", INFO),
    "kTCCServiceSystemPolicyAllFiles": ("Full Disk Access", "can read all your files, mail and messages", INFO),
}

# Names of Apple background processes. One of these running from anywhere else is wearing a disguise.
APPLE_PROCESS_NAMES = {"launchd", "kernel_task", "WindowServer", "loginwindow", "mds", "mds_stores", "mdworker",
                       "cfprefsd", "distnoted", "trustd", "syslogd", "securityd", "coreaudiod", "bluetoothd",
                       "airportd", "softwareupdated", "configd", "notifyd", "powerd", "Finder", "Dock",
                       "SystemUIServer", "sharingd", "rapportd", "nsurlsessiond", "cloudd", "bird", "akd"}
APPLE_PLACES = ("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/Applications/Safari.app/")

# Domains a malicious hosts file likes to redirect.
SENSITIVE_DOMAINS = re.compile(r"apple\.com|icloud|google|microsoft|windowsupdate|github|paypal|bank|"
                               r"malwarebytes|norton|avast|kaspersky|bitdefender|sophos|crowdstrike|"
                               r"objective-see|virustotal|telegram|whatsapp", re.IGNORECASE)

SHELL_STARTUP_FILES = [".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile",
                       ".bash_login", ".ssh/rc"]

SUSPICIOUS_SHELL_LINES = [
    ("downloads and runs code every time you open a terminal",
     r"(?:curl|wget)[^|\n#]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|base64\s+(?:-d|-D|--decode)[^\n]*\|\s*(?:ba|z)?sh"),
    ("opens a reverse shell", r"/dev/tcp/|\bnc\b[^\n]*\s-e\s|\bncat\b[^\n]*\s-e\s"),
    ("replaces sudo (a trick to capture your password)", r"^\s*alias\s+sudo\s*=|^\s*(?:function\s+)?sudo\s*\(\)"),
    ("runs a hidden program in the background", r"nohup\s+[^\n]*/\.[\w.-]+/[^\n]*&|\(\s*[^\n]*/\.[\w.-]+/[^\n]*&\s*\)"),
    ("runs encoded Python", r"python3?\s+-c\s+[\"'][^\n]*(?:b64decode|exec\()"),
]


# ---------------------------------------------------------------------------------------------
# Talking to the system
# ---------------------------------------------------------------------------------------------

class Mac:
    """Everything rathunter knows how to ask the system. Tests replace `run` and `home`."""

    def __init__(self, home=None, root="/"):
        self.home = Path(home or Path.home())
        self.root = Path(root)          # prefix for system paths like /Library (tests point it at a temp folder)
        self._commands = {}
        self._signatures = {}

    def path(self, system_path):
        return self.root / system_path.lstrip("/")

    def run(self, *command):
        """Run a read-only system command and return what it printed ("" if it failed or isn't there)."""
        if command not in self._commands:
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                        encoding="utf-8", errors="replace")
                self._commands[command] = result.stdout + result.stderr
            except (OSError, subprocess.TimeoutExpired):
                self._commands[command] = ""
        return self._commands[command]

    def signature(self, path):
        """Who signed this program: ("apple" | "appstore" | "developer" | "adhoc" | "unsigned" | "missing" |
    "unreadable", name)."""
        path = str(path)
        if path not in self._signatures:
            self._signatures[path] = read_signature(self.run("codesign", "-dv", "--verbose=2", path), path)
        return self._signatures[path]


def read_signature(output, path):
    if not os.path.exists(path):
        return ("missing", None)
    if "Permission denied" in output or "Operation not permitted" in output:
        return ("unreadable", None)
    if "not signed at all" in output:
        return ("unsigned", None)
    if "Signature=adhoc" in output:
        return ("adhoc", None)
    authority = re.search(r"^Authority=(.+)$", output, re.MULTILINE)
    authority = authority.group(1).strip() if authority else ""
    if authority == "Software Signing" or "Apple Code Signing" in authority:
        return ("apple", "Apple")
    if authority.startswith("Apple Mac OS Application Signing"):
        return ("appstore", "the App Store")
    if authority.startswith("Developer ID Application:"):
        return ("developer", re.sub(r"\s*\([A-Z0-9]+\)$", "", authority.split(":", 1)[1].strip()).rstrip("."))
    if authority.startswith("Apple Development:") or authority.startswith("Mac Developer:"):
        return ("adhoc", None)   # a development build: not notarized for distribution
    return ("unsigned", None) if not output.strip() else ("developer", authority or "an unknown developer")


def finding(severity, category, title, detail, fix=None, where=None, skipped=False):
    item = {"severity": severity, "category": category, "title": title, "detail": detail, "fix": fix, "where": where}
    if skipped:
        item["skipped"] = True   # this check couldn't run; never let a report show it as "clear"
    return item


def tidy(path, home):
    """Show paths under your home folder as ~/... so reports don't reveal your username."""
    return str(path).replace(str(home), "~")


def is_shady_place(path):
    text = str(path)
    if text.startswith(SHADY_PLACES) or "/Downloads/" in text:
        return True
    # a hidden folder anywhere in the path (but not the many legit ones under ~/.config, ~/.local, etc.)
    parts = Path(text).parts[:-1]
    return any(p.startswith(".") and p not in (".", "..", ".config", ".local", ".cache", ".nvm", ".pyenv",
                                               ".rbenv", ".cargo", ".rustup", ".volta", ".bun", ".deno",
                                               ".npm", ".docker", ".orbstack", ".colima", ".lima", ".vscode",
                                               ".cursor", ".claude", ".codex", ".gemini", ".ollama", ".asdf",
                                               ".sdkman", ".jenv", ".gem", ".poetry", ".pixi", ".juliaup",
                                               ".foundry", ".dotnet", ".ghcup", ".mint", ".swiftpm", ".app")
               for p in parts)


def read_text(path, limit=300_000):
    try:
        with open(path, "rb") as f:
            data = f.read(limit)
    except OSError:
        return None
    if b"\0" in data[:2000]:   # a binary file, not a script
        return None
    return data.decode("utf-8", errors="replace")


def rat_signs(text):
    """Which RAT behaviours a script shows, as plain-English labels."""
    if not text:
        return []
    return [label for label, pattern in RAT_SIGNS if re.search(pattern, text, re.IGNORECASE)]


def split_command(args):
    """For ["python3", "-u", "/x/agent.py"] return ("python3", "/x/agent.py", None).
    For ["bash", "-c", "curl ... | sh"] return ("bash", None, "curl ... | sh")."""
    program = os.path.basename(args[0]) if args else ""
    if re.sub(r"[\d.]+$", "", program) not in {re.sub(r"[\d.]+$", "", i) for i in INTERPRETERS}:
        return program, None, None
    rest = list(args[1:])
    if program == "env":
        while rest and (rest[0].startswith("-") or "=" in rest[0]):
            rest.pop(0)
        return split_command(rest) if rest else (program, None, None)
    for i, arg in enumerate(rest):
        if arg in ("-c", "-e") and i + 1 < len(rest):
            return program, None, rest[i + 1]
        if not arg.startswith("-"):
            return program, arg, None
    return program, None, None


# ---------------------------------------------------------------------------------------------
# 1. What starts by itself
# ---------------------------------------------------------------------------------------------

def judge_program(mac, args):
    """Look at what a startup item runs. Returns (severity, plain-English description, evidence)."""
    program, script, inline = split_command(args)
    executable = args[0] if args else ""
    if script or inline:
        text = inline if inline else read_text(script)
        signs = rat_signs(text)
        where = script or f"{program} -c …"
        if signs:
            return DANGER, f"runs a script that {join(signs)}", where
        if script and is_shady_place(script):
            return DANGER, "runs a script hidden in a temporary or hidden folder", where
        if inline:
            return WARNING, f"runs a {program} command directly instead of an app", where
        return WARNING, f"runs a {program} script instead of an app", where
    if is_shady_place(executable):
        kind, _ = mac.signature(executable)
        if kind in ("unsigned", "adhoc", "missing"):
            return DANGER, "runs an unsigned program from a temporary or hidden folder", executable
    kind, signer = mac.signature(executable)
    if kind in ("apple", "appstore"):
        return INFO, f"signed by {signer}", executable
    if kind == "developer":
        return INFO, f"signed by {signer}", executable
    if kind == "missing":
        return INFO, "points to a program that no longer exists (a leftover from an uninstalled app)", executable
    if kind == "unreadable":
        return INFO, "only root can read this program, so its signature wasn't checked (run with sudo to check it)", executable
    if executable.startswith(PACKAGE_MANAGERS):
        return INFO, "installed by a package manager (Homebrew, MacPorts or Nix)", executable
    text = read_text(executable, 4000)
    if text is not None and text.startswith("#!"):
        signs = rat_signs(read_text(executable))
        if signs:
            return DANGER, f"runs a script that {join(signs)}", executable
        return WARNING, "runs a script instead of a signed app", executable
    return WARNING, "runs a program that isn't signed by a known developer", executable


def join(items):
    items = list(dict.fromkeys(items))
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def check_launch_items(mac):
    """Launch agents (start when you log in) and launch daemons (start at boot, as root)."""
    found = []
    places = [(mac.home / "Library/LaunchAgents", "Starts when you log in"),
              (mac.path("/Library/LaunchAgents"), "Starts when anyone logs in"),
              (mac.path("/Library/LaunchDaemons"), "Starts at boot, as root")]
    for folder, when in places:
        if not folder.is_dir():
            continue
        for plist in sorted(folder.iterdir()):
            if plist.suffix != ".plist":
                continue
            try:
                with open(plist, "rb") as f:
                    item = plistlib.load(f)
            except Exception:
                found.append(finding(WARNING, "Starts automatically", plist.name,
                                     f"{when}, but its settings file can't be read. Malware sometimes "
                                     "corrupts these on purpose to resist inspection.", where=tidy(plist, mac.home)))
                continue
            args = item.get("ProgramArguments") or []
            if item.get("Program"):
                args = [item["Program"]] + list(args[1:] if args else [])
            args = [str(a) for a in args]
            if not args:
                continue
            severity, what, evidence = judge_program(mac, args)
            label = item.get("Label", plist.stem)
            if label.startswith("com.apple.") and severity != INFO:
                severity, what = DANGER, f"pretends to be part of macOS (\"{label}\") but {what}"
            fix = None
            if severity != INFO:
                quoted = '"' + str(plist).replace(str(mac.home), "$HOME") + '"'   # $HOME works inside quotes, ~ doesn't
                if folder == mac.home / "Library/LaunchAgents":
                    fix = f"launchctl bootout gui/$(id -u) {quoted}\nmv {quoted} ~/Desktop/   # keep it for a closer look"
                else:   # system-wide items need sudo
                    fix = f"sudo launchctl bootout system {quoted}\nsudo mv {quoted} ~/Desktop/   # keep it for a closer look"
            found.append(finding(severity, "Starts automatically", label, f"{when}: {what}.", fix,
                                 tidy(evidence, mac.home)))
    return found


def check_login_hooks(mac):
    """Login and logout hooks: an old macOS feature that runs a script as root every time someone logs in."""
    found = []
    plist = mac.path("/Library/Preferences/com.apple.loginwindow.plist")
    try:
        with open(plist, "rb") as f:
            prefs = plistlib.load(f)
    except Exception:
        return found
    for key in ("LoginHook", "LogoutHook"):
        if prefs.get(key):
            severity, what, evidence = judge_program(mac, [str(prefs[key])])
            found.append(finding(DANGER if severity == DANGER else WARNING, "Starts automatically", key,
                                 f"Runs as root every time someone logs {'in' if key == 'LoginHook' else 'out'}: "
                                 f"{what}. Apple deprecated this years ago, and malware still uses it.",
                                 f"sudo defaults delete com.apple.loginwindow {key}", tidy(evidence, mac.home)))
    return found


def check_cron(mac):
    """Scheduled jobs. Rare on Macs, and a favourite of malware ported from Linux."""
    found = []
    jobs = []
    listing = mac.run("crontab", "-l")
    if listing and "no crontab" not in listing:
        jobs += [("your crontab", line) for line in listing.splitlines()]
    for path in ("/etc/crontab",):
        text = read_text(mac.path(path))
        if text:
            jobs += [(path, line) for line in text.splitlines()]
    for source, line in jobs:
        line = line.strip()
        if not line or line.startswith("#") or re.match(r"^[A-Z_]+=", line):
            continue
        signs = rat_signs(line)
        script = next((t for t in line.split() if t.startswith("/") and os.path.isfile(t)), None)
        if script:
            signs += rat_signs(read_text(script))
        hidden = bool(re.search(r"/\.[\w.-]+/|/tmp/|/Users/Shared/", line))
        severity = DANGER if signs or hidden else WARNING
        detail = "A scheduled job runs this command over and over"
        detail += f", and it {join(signs)}." if signs else (" from a hidden or temporary folder." if hidden else ".")
        found.append(finding(severity, "Starts automatically", f"Scheduled job in {source}", detail,
                             "crontab -e   # delete the line if you don't recognize it", line[:200]))
    return found


def check_shell_startup(mac):
    """Files your terminal runs every time it opens. One line here is enough to steal a password."""
    found = []
    for name in SHELL_STARTUP_FILES:
        path = mac.home / name
        text = read_text(path)
        if not text:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for what, pattern in SUSPICIOUS_SHELL_LINES:
                if re.search(pattern, line, re.IGNORECASE):
                    found.append(finding(DANGER, "Starts automatically", f"{tidy(path, mac.home)}, line {number}",
                                         f"Every time you open a terminal, this line {what}.",
                                         f"Open {tidy(path, mac.home)} and remove line {number} if you didn't write it.",
                                         line.strip()[:200]))
                    break
    return found


# ---------------------------------------------------------------------------------------------
# 2. What can watch you
# ---------------------------------------------------------------------------------------------

def check_privacy_permissions(mac):
    """Apps you've allowed to see your screen, read your keyboard, use your camera, and so on."""
    found = []
    databases = [mac.home / "Library/Application Support/com.apple.TCC/TCC.db",
                 mac.path("/Library/Application Support/com.apple.TCC/TCC.db")]
    rows, readable = [], False
    for db in databases:
        try:
            connection = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
            rows += connection.execute("SELECT service, client, client_type, auth_value FROM access").fetchall()
            connection.close()
            readable = True
        except sqlite3.Error:
            continue
    if not readable:
        return [finding(INFO, "Can watch you", "Privacy permissions not checked",
                        "macOS protects the list of apps that can record your screen, read your keyboard, or use "
                        "your camera. rathunter can read it only if your terminal app has Full Disk Access.",
                        "System Settings → Privacy & Security → Full Disk Access → turn on your terminal app, "
                        "then run rathunter again. Or check these panes by hand: Screen Recording, Input "
                        "Monitoring, Accessibility, Camera, Microphone.", skipped=True)]
    allowed = {}
    for service, client, client_type, auth in rows:
        if service in PRIVACY and auth == 2:
            allowed.setdefault((client, client_type), []).append(service)
    for (client, client_type), services in sorted(allowed.items()):
        names = [PRIVACY[s][0] for s in services]
        powers = [PRIVACY[s][1] for s in services]
        severity = min((PRIVACY[s][2] for s in services), key=RANK.get)
        is_path = client_type == 1
        if is_path:
            text = read_text(client)
            signs = rat_signs(text)
            if signs or is_shady_place(client):
                severity = DANGER
                detail = (f"A program in {'a hidden or temporary folder' if is_shady_place(client) else 'your files'}"
                          f" has {join(names)}: it {join(powers)}" + (f", and it {join(signs)}." if signs else "."))
            else:
                kind, signer = mac.signature(client)
                if kind in ("apple", "appstore", "developer") and severity == WARNING:
                    severity = INFO
                detail = f"This program {join(powers)} ({join(names)})."
        else:
            if client.startswith("com.apple."):
                continue
            # A real installed app (macOS knows it by its bundle id). Listed so you can see who has access,
            # but not alarming: video calls, screen sharing and automation tools all need these.
            severity = INFO
            detail = f"This app {join(powers)} ({join(names)}). Make sure you recognize it."
        if severity == WARNING:
            detail += " That's normal for screen sharing, automation and accessibility tools. Make sure you recognize it."
        found.append(finding(severity, "Can watch you", client.rsplit("/", 1)[-1] if is_path else client, detail,
                             "System Settings → Privacy & Security → " + names[0] +
                             " → turn it off if you don't recognize it." if severity != INFO else None,
                             tidy(client, mac.home)))
    return found


# ---------------------------------------------------------------------------------------------
# 3. What can reach in
# ---------------------------------------------------------------------------------------------

def listening_sockets(mac):
    """(port, address, pid) for every TCP port this Mac is listening on, from any user."""
    sockets = []
    for line in mac.run("netstat", "-anv", "-p", "tcp").splitlines():
        if "LISTEN" not in line:
            continue
        parts = line.split()
        local = parts[3] if len(parts) > 3 else ""
        address, _, port = local.rpartition(".")
        pid = re.search(r":(\d+)\s", line)
        if port.isdigit():
            sockets.append((int(port), address, int(pid.group(1)) if pid else None))
    return sockets


def check_remote_access(mac):
    found = []
    sockets = listening_sockets(mac)
    open_ports = {port for port, address, _ in sockets if address not in ("127.0.0.1", "::1")}
    for port, what in REMOTE_PORTS.items():
        if port in open_ports:
            found.append(finding(WARNING, "Can reach in", f"{what} is on",
                                 f"Other computers can connect to this Mac on port {port}. Fine if you turned it "
                                 "on yourself; otherwise someone may be using it to get in.",
                                 "System Settings → General → Sharing → turn off what you don't use."))
    keys = read_text(mac.home / ".ssh/authorized_keys")
    if keys and keys.strip():
        count = sum(1 for line in keys.splitlines() if line.strip() and not line.startswith("#"))
        comments = [line.split()[-1] for line in keys.splitlines() if len(line.split()) >= 3]
        ssh_on = 22 in open_ports
        found.append(finding(WARNING if ssh_on else INFO, "Can reach in",
                             f"{count} SSH {'key is' if count == 1 else 'keys are'} allowed to log in as you",
                             ("Remote Login is on, so whoever holds " + ("this key" if count == 1 else "these keys") +
                              " can log in without your password." if ssh_on else
                              "They only matter if Remote Login is turned on (it isn't right now).") +
                             (f" Key labels: {', '.join(comments[:5])}." if comments else ""),
                             "Remove lines you don't recognize from ~/.ssh/authorized_keys." if ssh_on else None,
                             "~/.ssh/authorized_keys"))
    apps = installed_apps(mac)
    running = mac.run("ps", "-axo", "comm=")
    for name in REMOTE_APPS:
        match = next((a for a in apps if name.lower() in a.lower()), None)
        if not match:
            continue
        is_running = name.lower().replace(" ", "") in running.lower().replace(" ", "")
        found.append(finding(WARNING if is_running else INFO, "Can reach in", match,
                             f"A remote-control app is installed{' and running' if is_running else ''}. It lets "
                             "someone see and control this Mac. Scammers and stalkers install these too.",
                             f"If you didn't install it, quit it and move it to the Trash." if is_running else None))
    return found


def installed_apps(mac):
    apps = []
    for folder in (mac.path("/Applications"), mac.home / "Applications", mac.path("/Library/Application Support")):
        try:
            apps += [p.name for p in folder.iterdir()]
        except OSError:
            continue
    return apps


# ---------------------------------------------------------------------------------------------
# 4. What is running now
# ---------------------------------------------------------------------------------------------

def processes(mac):
    """{pid: (user, executable, full command line)} for every process."""
    found = {}
    for line in mac.run("ps", "-axww", "-o", "pid=,user=,comm=").splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            found[int(parts[0])] = [parts[1], parts[2], parts[2]]
    for line in mac.run("ps", "-axww", "-o", "pid=,args=").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit() and int(parts[0]) in found:
            found[int(parts[0])][2] = parts[1]
    return found


def check_processes(mac):
    found = []
    seen = set()
    for pid, (user, exe, command) in sorted(processes(mac).items()):
        name = os.path.basename(exe)
        if name in APPLE_PROCESS_NAMES and exe.startswith("/") and not exe.startswith(APPLE_PLACES):
            found.append(finding(DANGER, "Running now", f"Fake system process \"{name}\" (pid {pid})",
                                 f"It's named like a part of macOS but runs from {tidy(exe, mac.home)}. "
                                 "Real system processes never live there.",
                                 f"kill {pid}   # then find out what starts it (see Starts automatically)",
                                 tidy(exe, mac.home)))
            continue
        program, script, inline = split_command(command.split())
        if script and not script.startswith("/"):
            script = None
        key = script or inline or exe
        if key in seen:
            continue
        seen.add(key)
        if script or inline:
            signs = rat_signs(inline if inline else read_text(script))
            if signs:
                found.append(finding(DANGER, "Running now", f"{program} script (pid {pid})",
                                     f"A running script {join(signs)}.", f"kill {pid}   # then delete the script and "
                                     "whatever starts it", tidy(script or command[:200], mac.home)))
            elif script and is_shady_place(script):
                found.append(finding(WARNING, "Running now", f"{program} script (pid {pid})",
                                     "A script is running from a hidden or temporary folder.",
                                     "Make sure you know what it is.", tidy(script, mac.home)))
        elif exe.startswith("/") and is_shady_place(exe):
            kind, _ = mac.signature(exe)
            if kind in ("unsigned", "adhoc"):
                found.append(finding(DANGER, "Running now", f"{name} (pid {pid})",
                                     "An unsigned program is running from a hidden or temporary folder.",
                                     f"kill {pid}   # then find out what starts it", tidy(exe, mac.home)))
    return found


def check_connections(mac):
    """Scripts with open connections to the internet, especially to Telegram (the classic RAT control channel)."""
    found = []
    procs = processes(mac)
    for line in mac.run("netstat", "-anv", "-p", "tcp").splitlines():
        if "ESTABLISHED" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        remote_ip, _, remote_port = parts[4].rpartition(".")
        pid = re.search(r":(\d+)\s", line)
        try:
            ip = ipaddress.ip_address(remote_ip)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback:
            continue
        pid = int(pid.group(1)) if pid else None
        user, exe, command = procs.get(pid, ("?", "?", "?"))
        name = os.path.basename(exe)
        is_script = split_command(command.split())[1] is not None or split_command(command.split())[2] is not None \
            or re.sub(r"[\d.]+$", "", name) in INTERPRETERS
        telegram = any(ip in network for network in TELEGRAM_NETWORKS)
        if telegram and "telegram" not in exe.lower():
            found.append(finding(DANGER, "Running now", f"{name} is talking to Telegram (pid {pid})",
                                 "Something other than the Telegram app has an open connection to Telegram's "
                                 "servers. That's exactly how most Python RATs receive commands.",
                                 f"kill {pid}   # then delete it and whatever starts it", tidy(command[:200], mac.home)))
        elif is_script and remote_port not in ("443", "80"):
            found.append(finding(WARNING, "Running now", f"{name} has a raw connection to {remote_ip}:{remote_port}",
                                 "A script is connected to an internet address on an unusual port. Reverse shells "
                                 "look like this; so do some developer tools.",
                                 "Make sure you know what this script is.", tidy(command[:200], mac.home)))
    return found


# ---------------------------------------------------------------------------------------------
# 5. Who can read your traffic
# ---------------------------------------------------------------------------------------------

def check_profiles(mac):
    found = []
    listing = mac.run("profiles", "list")
    for identifier in re.findall(r"profileIdentifier:\s*(\S+)", listing):
        if identifier.startswith("com.apple.ManagedSettings"):
            continue   # Screen Time / Family Sharing settings, made by macOS itself
        found.append(finding(WARNING, "Can read your traffic", f"Configuration profile {identifier}",
                             "Profiles can install certificates, route your traffic through a VPN or proxy, and "
                             "lock settings. Companies and schools use them; so does stalkerware.",
                             "System Settings → General → Device Management (or Profiles) → remove it if you "
                             "don't know who installed it."))
    status = mac.run("profiles", "status", "-type", "enrollment")
    if re.search(r"MDM enrollment:\s*Yes", status):
        found.append(finding(INFO, "Can read your traffic", "This Mac is managed (MDM)",
                             "An organization can install apps, change settings and see information about this "
                             "Mac. Expected on a work or school computer."))
    return found


def check_certificates(mac):
    found = []
    for flag, whose in ((), "you"), (("-d",), "an administrator"):
        output = mac.run("security", "dump-trust-settings", *flag)
        for name in re.findall(r"^Cert \d+:\s*(.+)$", output, re.MULTILINE):
            found.append(finding(WARNING, "Can read your traffic", f"Trusted certificate: {name.strip()}",
                                 f"Added by {whose} as a trusted authority. Whoever holds its key can read and "
                                 "change your HTTPS traffic. Debugging proxies (Charles, mitmproxy, Proxyman) add "
                                 "these on purpose; spyware does too.",
                                 "Keychain Access → find the certificate → delete it if you don't use a tool "
                                 "that needs it."))
    return found


def check_proxy(mac):
    found = []
    output = mac.run("scutil", "--proxy")
    for kind, enable, host in (("Web", "HTTPEnable", "HTTPProxy"), ("Secure web", "HTTPSEnable", "HTTPSProxy"),
                               ("SOCKS", "SOCKSEnable", "SOCKSProxy")):
        if re.search(rf"\b{enable}\s*:\s*1", output):
            server = re.search(rf"\b{host}\s*:\s*(\S+)", output)
            found.append(finding(WARNING, "Can read your traffic", f"{kind} proxy is on",
                                 f"Your traffic is being sent through {server.group(1) if server else 'a proxy'}. "
                                 "Fine for a work proxy or a debugging tool; otherwise someone may be watching it.",
                                 "System Settings → Network → your connection → Details → Proxies."))
    if re.search(r"\bProxyAutoConfigEnable\s*:\s*1", output):
        url = re.search(r"\bProxyAutoConfigURLString\s*:\s*(\S+)", output)
        found.append(finding(WARNING, "Can read your traffic", "Automatic proxy configuration is on",
                             f"A script ({url.group(1) if url else 'unknown'}) decides where your traffic goes.",
                             "System Settings → Network → your connection → Details → Proxies."))
    return found


def check_hosts_file(mac):
    found = []
    text = read_text(mac.path("/etc/hosts")) or ""
    for number, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) < 2:
            continue
        names = [n for n in parts[1:] if n not in ("localhost", "broadcasthost", "localhost.localdomain")]
        if not names:
            continue
        sensitive = [n for n in names if SENSITIVE_DOMAINS.search(n)]
        blocked = parts[0] in ("0.0.0.0", "127.0.0.1", "::1", "::")
        if sensitive and not blocked:
            found.append(finding(DANGER, "Can read your traffic", f"/etc/hosts redirects {sensitive[0]}",
                                 f"Visits to {join(sensitive[:3])} are sent to {parts[0]} instead of the real site. "
                                 "That's how fake login pages get served.",
                                 f"sudo nano /etc/hosts   # delete line {number}", line))
        elif sensitive and blocked:
            found.append(finding(WARNING, "Can read your traffic", f"/etc/hosts blocks {sensitive[0]}",
                                 f"{join(sensitive[:3])} can't be reached. Malware blocks security sites and "
                                 "update servers this way; ad blockers and developers do it on purpose.",
                                 f"sudo nano /etc/hosts   # delete line {number} if you didn't add it", line))
    return found


# ---------------------------------------------------------------------------------------------
# 6. Browser extensions
# ---------------------------------------------------------------------------------------------

BROWSERS = {"Chrome": "Google/Chrome", "Brave": "BraveSoftware/Brave-Browser", "Edge": "Microsoft Edge",
            "Chromium": "Chromium", "Vivaldi": "Vivaldi", "Arc": "Arc/User Data", "Opera": "com.operasoftware.Opera"}
STORE_UPDATE_URLS = ("clients2.google.com", "edge.microsoft.com", "extension-updates.opera.com")
POWERFUL = {"cookies": "read your cookies (stay logged in as you)", "webRequest": "watch your web traffic",
            "debugger": "fully control pages", "nativeMessaging": "talk to programs on your Mac",
            "proxy": "route your traffic", "clipboardRead": "read your clipboard",
            "history": "read your browsing history"}


def extension_name(manifest, folder):
    name = manifest.get("name", folder.parent.name)
    match = re.fullmatch(r"__MSG_(\w+)__", name)
    if match:
        for locale in (manifest.get("default_locale", "en"), "en", "en_US"):
            try:
                messages = json.loads((folder / "_locales" / locale / "messages.json").read_text(encoding="utf-8-sig"))
                for key, value in messages.items():
                    if key.lower() == match.group(1).lower():
                        return value.get("message", name)
            except (OSError, ValueError):
                continue
    return name


def check_browser_extensions(mac):
    found = []
    for browser, folder in BROWSERS.items():
        base = mac.home / "Library/Application Support" / folder
        for manifest_path in sorted(base.glob("*/Extensions/*/*/manifest.json")):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError):
                continue
            name = extension_name(manifest, manifest_path.parent)
            permissions = [p for p in manifest.get("permissions", []) + manifest.get("host_permissions", [])
                           if isinstance(p, str)]
            hosts = permissions + [m for cs in manifest.get("content_scripts", []) for m in cs.get("matches", [])]
            every_site = any(h in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for h in hosts)
            powers = [POWERFUL[p] for p in permissions if p in POWERFUL]
            sideloaded = not str(manifest.get("update_url", "")).replace("https://", "").startswith(STORE_UPDATE_URLS)
            if every_site:
                powers.insert(0, "read and change every website you visit")
            if sideloaded and (every_site or powers):
                found.append(finding(WARNING, "Browser extensions", f"{name} ({browser})",
                                     "Installed from outside the extension store, and it can " + join(powers or ["run"]) +
                                     ". Sideloaded extensions are a common way to steal logins.",
                                     f"{browser} → Extensions → remove it if you didn't install it.",
                                     tidy(manifest_path.parent, mac.home)))
            elif every_site and len(powers) >= 3:
                found.append(finding(INFO, "Browser extensions", f"{name} ({browser})",
                                     "Can " + join(powers) + ". Fine for an ad blocker or password manager you trust.",
                                     None, tidy(manifest_path.parent, mac.home)))
    return found


# ---------------------------------------------------------------------------------------------
# 7. Your defenses
# ---------------------------------------------------------------------------------------------

def check_defenses(mac):
    found = []
    if "disabled" in mac.run("csrutil", "status").lower():
        found.append(finding(WARNING, "Your defenses", "System Integrity Protection is off",
                             "macOS can't stop programs from modifying the system. Rootkits need this off.",
                             "csrutil enable   # run this in Recovery mode: restart holding the power button → Options → Utilities → Terminal"))
    if "disabled" in mac.run("spctl", "--status").lower():
        found.append(finding(WARNING, "Your defenses", "Gatekeeper is off",
                             "Any downloaded app can run without being checked by Apple first.",
                             "sudo spctl --global-enable"))
    filevault = mac.run("fdesetup", "status")
    if "FileVault is Off" in filevault:
        found.append(finding(WARNING, "Your defenses", "FileVault is off",
                             "Anyone who gets your Mac can read your files by plugging the disk into another computer.",
                             "System Settings → Privacy & Security → FileVault → Turn On."))
    firewall = mac.run("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
    if "disabled" in firewall.lower():
        found.append(finding(INFO, "Your defenses", "Firewall is off",
                             "macOS ships with it off. Turning it on blocks unexpected incoming connections.",
                             "System Settings → Network → Firewall → turn on."))
    extensions = mac.run("systemextensionsctl", "list")
    for team, bundle, state in re.findall(r"^\s*\*?\s*\*?\s*([A-Z0-9]{10})\s+(\S+)\s+\([^)]*\)\s+.*\[([^\]]+)\]",
                                          extensions, re.MULTILINE):
        found.append(finding(INFO, "Your defenses", f"System extension {bundle}",
                             f"Runs with deep access to the system ({state}). Usually a VPN, security or "
                             "virtualization tool."))
    return found


# ---------------------------------------------------------------------------------------------
# Putting it together
# ---------------------------------------------------------------------------------------------

CHECKS = [
    ("Startup items", check_launch_items), ("Login hooks", check_login_hooks), ("Scheduled jobs", check_cron),
    ("Terminal startup files", check_shell_startup), ("Privacy permissions", check_privacy_permissions),
    ("Remote access", check_remote_access), ("Running programs", check_processes),
    ("Network connections", check_connections), ("Configuration profiles", check_profiles),
    ("Trusted certificates", check_certificates), ("Proxies", check_proxy), ("Hosts file", check_hosts_file),
    ("Browser extensions", check_browser_extensions), ("System defenses", check_defenses),
]


def scan(mac, progress=None):
    findings, checked = [], []
    for name, check in CHECKS:
        if progress:
            progress(name)
        try:
            results = check(mac)
        except Exception as error:   # one broken check shouldn't stop the others
            results = [finding(INFO, "Your defenses", f"{name}: check failed", f"{type(error).__name__}: {error}",
                               skipped=True)]
        for result in results:
            result["check"] = name
        findings += results
        checked.append(name)
    findings.sort(key=lambda f: (CATEGORIES.index(f["category"]), RANK[f["severity"]], f["title"].lower()))
    return {"tool": "rathunter", "version": VERSION, "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "system": f"macOS {platform.mac_ver()[0]}", "checked": checked, "findings": findings,
            "verdict": verdict(findings)}


def verdict(findings):
    dangers = sum(f["severity"] == DANGER for f in findings)
    warnings = sum(f["severity"] == WARNING for f in findings)
    if dangers:
        return {"level": DANGER, "headline": "Possible spyware found",
                "summary": f"{dangers} {'thing looks' if dangers == 1 else 'things look'} like spyware or a RAT. "
                           "Read each one below before deleting anything."}
    if warnings:
        return {"level": WARNING, "headline": "No spyware found, but check these",
                "summary": f"{warnings} {'thing is' if warnings == 1 else 'things are'} worth a look. "
                           "Most will be things you set up yourself."}
    skipped = sum(bool(f.get("skipped")) for f in findings)
    note = f" ({skipped} {'check was' if skipped == 1 else 'checks were'} skipped: see below.)" if skipped else ""
    return {"level": "clean", "headline": "No signs of spyware",
            "summary": "Nothing on this Mac looks like a RAT, stalkerware or spyware." + note}


# ---------------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------------

def print_report(result, show_all, color):
    paint = (lambda code, text: f"\033[{code}m{text}\033[0m") if color else (lambda code, text: text)
    style = {DANGER: ("1;31", "✖ DANGER "), WARNING: ("1;33", "! REVIEW "), INFO: ("2", "· info   ")}
    v = result["verdict"]
    head = {"danger": "1;41;97", "warning": "1;43;30", "clean": "1;42;30"}[v["level"]]
    print()
    print(paint(head, f"  {v['headline']}  "))
    print(v["summary"])
    skipped = [f for f in result["findings"] if f.get("skipped")]
    done = [c for c in result["checked"] if c not in {f["check"] for f in skipped}]
    print(paint("2", f"Checked: {', '.join(done)}."))
    for f in skipped:
        print(paint("33", f"Not checked: {f['check']}. ") + paint("2", f["fix"] or f["detail"]))
    shown = [f for f in result["findings"] if show_all or (f["severity"] != INFO and not f.get("skipped"))]
    category = None
    for f in shown:
        if f["category"] != category:
            category = f["category"]
            print("\n" + paint("1", category.upper()))
        code, label = style[f["severity"]]
        print(f"  {paint(code, label)}{paint('1', f['title'])}")
        print(f"           {f['detail']}")
        if f.get("where"):
            print(paint("2", f"           ↳ {f['where']}"))
        if f.get("fix"):
            for i, line in enumerate(f["fix"].splitlines()):
                print(paint("36", f"           {'Fix: ' if i == 0 else '     '}{line}"))
    hidden = len([f for f in result["findings"] if not f.get("skipped")]) - len([f for f in shown if not f.get("skipped")])
    if hidden:
        print(paint("2", f"\n{hidden} more items looked fine. See them with --all, or as a report with --html report.html"))
    print()


def render_html(result, output):
    template = (Path(__file__).resolve().parent / "report.html").read_text(encoding="utf-8")
    data = json.dumps(result, ensure_ascii=False).replace("</", "<\\/")
    Path(output).write_text(template.replace("/*__RESULT__*/null", data), encoding="utf-8")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Is someone spying on your Mac? Find RATs, stalkerware and spyware.")
    parser.add_argument("--all", action="store_true", help="also show items that looked fine")
    parser.add_argument("--html", metavar="FILE", help="write a visual report to FILE")
    parser.add_argument("--open", action="store_true", help="open the HTML report in your browser")
    parser.add_argument("--json", action="store_true", help="print the results as JSON")
    parser.add_argument("--no-color", action="store_true", help="plain text output")
    parser.add_argument("--version", action="version", version=f"rathunter {VERSION}")
    args = parser.parse_args()

    if sys.platform != "darwin":
        sys.exit("rathunter checks macOS for now. Windows and Linux support is on the roadmap: " + PROJECT_URL)

    color = sys.stdout.isatty() and not args.no_color and not args.json
    progress = None
    if color:
        progress = lambda name: print(f"\r\033[2K\033[2mChecking {name.lower()}…\033[0m", end="", flush=True)
    result = scan(Mac(), progress)
    if color:
        print("\r\033[2K", end="")

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_report(result, args.all, color)
    if args.html or args.open:
        output = args.html or "rathunter-report.html"
        render_html(result, output)
        if not args.json:
            print(f"Report written to {output}")
        if args.open:
            webbrowser.open(Path(output).resolve().as_uri())
    sys.exit({"danger": 2, "warning": 1, "clean": 0}[result["verdict"]["level"]])


if __name__ == "__main__":
    main()
