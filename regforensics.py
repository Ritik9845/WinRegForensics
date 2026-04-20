#!/usr/bin/env python3
"""
==============================================================================
 WinRegForensics - Windows Registry Memory Forensics Tool
 Author: For educational/forensics use only
 Requires: volatility3, python-registry, tabulate, colorama
==============================================================================
"""

import argparse
import sys
import os
import json
import csv
import hashlib
import struct
import binascii
from datetime import datetime, timezone
from pathlib import Path

# ── Dependency checks ────────────────────────────────────────────────────────
try:
    import volatility3
    from volatility3 import framework
    from volatility3.framework import contexts, automagic, interfaces
    from volatility3.framework.configuration import requirements
    from volatility3.plugins.windows import registry
    from volatility3.plugins.windows.registry import hivelist, printkey, hivedump
    from volatility3.plugins.windows.registry import userassist, shellbags
    HAS_VOL3 = True
except ImportError:
    HAS_VOL3 = False

try:
    from Registry import Registry  # python-registry
    HAS_PYREG = True
except ImportError:
    HAS_PYREG = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

# ── Color helpers ─────────────────────────────────────────────────────────────
def c(text, color=""):
    if HAS_COLOR and color:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

def banner():
    b = r"""
  ██████╗ ███████╗ ██████╗    ███████╗ ██████╗ ██████╗
  ██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔═══██╗██╔══██╗
  ██████╔╝█████╗  ██║  ███╗   █████╗  ██║   ██║██████╔╝
  ██╔══██╗██╔══╝  ██║   ██║   ██╔══╝  ██║   ██║██╔══██╗
  ██║  ██║███████╗╚██████╔╝   ██║     ╚██████╔╝██║  ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝
  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
    Windows Registry Memory Forensics Tool  |  For Education & Research
    """
    print(c(b, Fore.CYAN if HAS_COLOR else ""))
    print(c("  [!] For authorized forensic analysis only\n", Fore.YELLOW if HAS_COLOR else ""))


# ── Volatility3 Context Builder ───────────────────────────────────────────────
def build_vol3_context(mem_image: str):
    """Initialize a Volatility3 context for the given memory image."""
    if not HAS_VOL3:
        raise RuntimeError("volatility3 is not installed. Run: pip install volatility3")
    ctx = contexts.Context()
    single_location = f"file://{os.path.abspath(mem_image)}"
    ctx.config["automagic.LayerStacker.single_location"] = single_location
    available_automagic = automagic.available(ctx)
    automagic.run(available_automagic, ctx, interfaces.plugins.PluginInterface, "")
    return ctx


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 – Hive Enumeration
# ══════════════════════════════════════════════════════════════════════════════
class HiveEnumerator:
    """List all loaded registry hives from a memory dump."""

    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        print(c("\n[*] Enumerating Registry Hives...", Fore.GREEN if HAS_COLOR else ""))
        try:
            plugin = hivelist.HiveList(self.ctx, config_path="plugins.HiveList", progress_callback=None)
            results = []
            for hive in plugin.run():
                results.append({
                    "Offset":    hex(hive.vol.offset),
                    "FileFullPath": str(hive.FileFullPath or ""),
                    "Name":      str(hive.Name or ""),
                })
            _print_table(results, ["Offset", "Name", "FileFullPath"])
            return results
        except Exception as e:
            print(c(f"  [-] HiveList error: {e}", Fore.RED if HAS_COLOR else ""))
            return []


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 – Key / Value Browser
# ══════════════════════════════════════════════════════════════════════════════
class RegistryKeyBrowser:
    """Print registry keys and values from a hive offset."""

    def __init__(self, ctx):
        self.ctx = ctx

    def print_key(self, hive_offset: int, key_path: str):
        print(c(f"\n[*] Reading key: {key_path}", Fore.GREEN if HAS_COLOR else ""))
        try:
            self.ctx.config["plugins.PrintKey.offset"] = hive_offset
            self.ctx.config["plugins.PrintKey.key"] = key_path
            plugin = printkey.PrintKey(self.ctx, config_path="plugins.PrintKey", progress_callback=None)
            results = []
            for key in plugin.run():
                row = {
                    "LastWrite": _filetime_to_dt(key.LastWriteTime.QuadPart),
                    "Type":      str(key.Type or ""),
                    "Name":      str(key.Name or ""),
                    "Data":      _format_value(key),
                }
                results.append(row)
            _print_table(results, ["LastWrite", "Type", "Name", "Data"])
            return results
        except Exception as e:
            print(c(f"  [-] PrintKey error: {e}", Fore.RED if HAS_COLOR else ""))
            return []


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 – SAM Database Parser
# ══════════════════════════════════════════════════════════════════════════════
class SAMParser:
    """
    Extract user accounts and password hashes from the SAM hive.
    Works on a dumped SAM file (use --dump-hive first to extract it).
    """

    SAM_KEY    = "SAM\\Domains\\Account\\Users"
    NAMES_KEY  = "SAM\\Domains\\Account\\Users\\Names"

    def __init__(self, sam_path: str, system_path: str = None):
        self.sam_path    = sam_path
        self.system_path = system_path

    def run(self):
        print(c("\n[*] Parsing SAM Database...", Fore.GREEN if HAS_COLOR else ""))
        if not HAS_PYREG:
            print(c("  [-] python-registry not installed. Run: pip install python-registry", Fore.RED if HAS_COLOR else ""))
            return []

        try:
            sam_reg = Registry.Registry(self.sam_path)
        except Exception as e:
            print(c(f"  [-] Cannot open SAM: {e}", Fore.RED if HAS_COLOR else ""))
            return []

        syskey = None
        if self.system_path:
            syskey = self._extract_syskey()

        users = []
        try:
            names_key = sam_reg.open(self.NAMES_KEY)
            for sub in names_key.subkeys():
                username = sub.name()
                rid = self._get_rid(sam_reg, username)
                v_data = self._get_v_data(sam_reg, rid) if rid else b""
                user = {
                    "Username": username,
                    "RID":      rid or "N/A",
                    "LM Hash":  "N/A",
                    "NT Hash":  "N/A",
                    "Flags":    "N/A",
                }
                if v_data:
                    parsed = self._parse_v(v_data, syskey)
                    user.update(parsed)
                users.append(user)
        except Exception as e:
            print(c(f"  [-] SAM parse error: {e}", Fore.RED if HAS_COLOR else ""))

        _print_table(users, ["Username", "RID", "NT Hash", "LM Hash", "Flags"])
        return users

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _get_rid(self, reg, username):
        try:
            key = reg.open(f"{self.NAMES_KEY}\\{username}")
            for v in key.values():
                if v.name() == "(default)" or v.name() == "":
                    return v.raw_data()[:4]
            return None
        except Exception:
            return None

    def _get_v_data(self, reg, rid):
        try:
            rid_int = struct.unpack("<I", rid)[0] if isinstance(rid, bytes) else int(rid, 16)
            key_path = f"{self.SAM_KEY}\\{rid_int:08X}"
            key = reg.open(key_path)
            for v in key.values():
                if v.name() == "V":
                    return v.raw_data()
        except Exception:
            pass
        return b""

    def _parse_v(self, v_data: bytes, syskey=None) -> dict:
        """Extract NT/LM hashes from the V value binary blob."""
        result = {"LM Hash": "N/A", "NT Hash": "N/A", "Flags": "N/A"}
        try:
            # Offsets in the V structure (Win XP+ format)
            nt_off  = struct.unpack_from("<I", v_data, 0xA8)[0] + 0xCC
            nt_len  = struct.unpack_from("<I", v_data, 0xAC)[0]
            lm_off  = struct.unpack_from("<I", v_data, 0x9C)[0] + 0xCC
            lm_len  = struct.unpack_from("<I", v_data, 0xA0)[0]

            if nt_len >= 20:
                nt_hash_enc = v_data[nt_off:nt_off + nt_len]
                result["NT Hash"] = binascii.hexlify(nt_hash_enc).decode()
            if lm_len >= 20:
                lm_hash_enc = v_data[lm_off:lm_off + lm_len]
                result["LM Hash"] = binascii.hexlify(lm_hash_enc).decode()

            flags_off = struct.unpack_from("<I", v_data, 0x40)[0]
            result["Flags"] = hex(flags_off)
        except Exception:
            pass
        return result

    def _extract_syskey(self) -> bytes:
        """Derive syskey (bootkey) from SYSTEM hive LSA keys."""
        try:
            sys_reg = Registry.Registry(self.system_path)
            lsa_key_parts = ["JD", "Skew1", "GBG", "Data"]
            scramble = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
                        0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]
            key_material = b""
            for part in lsa_key_parts:
                k = sys_reg.open(f"ControlSet001\\Control\\Lsa\\{part}")
                class_name = k.classname()
                key_material += bytes.fromhex(class_name)
            syskey_raw = bytes([key_material[i] for i in scramble])
            return syskey_raw
        except Exception as e:
            print(c(f"  [!] Could not extract syskey: {e}", Fore.YELLOW if HAS_COLOR else ""))
            return None


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 – UserAssist (MRU / Execution History)
# ══════════════════════════════════════════════════════════════════════════════
class UserAssistAnalyzer:
    """Decode ROT-13 UserAssist keys to reveal program execution history."""

    USERASSIST_PATH = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

    def run_from_hive(self, hive_path: str):
        print(c("\n[*] Extracting UserAssist (Program Execution History)...", Fore.GREEN if HAS_COLOR else ""))
        if not HAS_PYREG:
            print(c("  [-] python-registry required.", Fore.RED if HAS_COLOR else ""))
            return []
        try:
            reg = Registry.Registry(hive_path)
            ua_key = reg.open(self.USERASSIST_PATH)
        except Exception as e:
            print(c(f"  [-] Cannot open UserAssist key: {e}", Fore.RED if HAS_COLOR else ""))
            return []

        results = []
        for guid_key in ua_key.subkeys():
            try:
                count_key = guid_key.find_subkey("Count")
                if not count_key:
                    continue
                for entry in count_key.values():
                    name_rot13 = entry.name().encode("rot_13") if entry.name() else ""
                    data = entry.raw_data()
                    count, last_run = self._parse_ua_data(data)
                    results.append({
                        "Application": name_rot13,
                        "Run Count":   count,
                        "Last Run":    last_run,
                        "GUID":        guid_key.name(),
                    })
            except Exception:
                continue
        _print_table(results, ["Application", "Run Count", "Last Run", "GUID"])
        return results

    def _parse_ua_data(self, data: bytes):
        try:
            count    = struct.unpack_from("<I", data, 4)[0]
            filetime = struct.unpack_from("<Q", data, 60)[0]
            last_run = _filetime_to_dt(filetime)
            return count, last_run
        except Exception:
            return "N/A", "N/A"


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 – Persistence Mechanisms
# ══════════════════════════════════════════════════════════════════════════════
class PersistenceAnalyzer:
    """Scan common registry persistence locations."""

    PERSISTENCE_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"SYSTEM\CurrentControlSet\Services",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"SOFTWARE\Classes\Exefile\Shell\Open\Command",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
        r"SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell",
    ]

    def run_from_hive(self, hive_path: str):
        print(c("\n[*] Scanning Persistence Mechanisms...", Fore.GREEN if HAS_COLOR else ""))
        if not HAS_PYREG:
            print(c("  [-] python-registry required.", Fore.RED if HAS_COLOR else ""))
            return []
        try:
            reg = Registry.Registry(hive_path)
        except Exception as e:
            print(c(f"  [-] Cannot open hive: {e}", Fore.RED if HAS_COLOR else ""))
            return []

        findings = []
        for key_path in self.PERSISTENCE_KEYS:
            try:
                key = reg.open(key_path)
                for val in key.values():
                    findings.append({
                        "Key":   key_path,
                        "Value": val.name() or "(default)",
                        "Data":  str(val.value())[:120],
                        "Type":  str(val.value_type_as_string()),
                        "Modified": _filetime_to_dt(key.timestamp() if hasattr(key, "timestamp") else 0),
                    })
            except Exception:
                continue

        if findings:
            _print_table(findings, ["Key", "Value", "Data", "Type", "Modified"])
        else:
            print(c("  [+] No persistence entries found.", Fore.GREEN if HAS_COLOR else ""))
        return findings


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 6 – Network Forensics (Recent Connections & Interfaces)
# ══════════════════════════════════════════════════════════════════════════════
class NetworkForensics:
    """Extract network-related registry artifacts."""

    KEYS = {
        "Network Interfaces":      r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        "Recent WiFi Networks":     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
        "Network Connections":      r"SYSTEM\CurrentControlSet\Control\Network",
        "DNS Cache (static)":       r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "Mapped Drives":            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures",
        "IE Zone Map":              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap",
        "Typed URLs":               r"SOFTWARE\Microsoft\Internet Explorer\TypedURLs",
        "OpenSaveMRU":              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        "Terminal Server Client":   r"SOFTWARE\Microsoft\Terminal Server Client\Servers",
    }

    def run_from_hive(self, hive_path: str):
        print(c("\n[*] Extracting Network Forensics Artifacts...", Fore.GREEN if HAS_COLOR else ""))
        if not HAS_PYREG:
            print(c("  [-] python-registry required.", Fore.RED if HAS_COLOR else ""))
            return {}

        try:
            reg = Registry.Registry(hive_path)
        except Exception as e:
            print(c(f"  [-] Cannot open hive: {e}", Fore.RED if HAS_COLOR else ""))
            return {}

        all_results = {}
        for label, key_path in self.KEYS.items():
            try:
                key = reg.open(key_path)
                rows = []
                for val in key.values():
                    rows.append({
                        "Name":  val.name(),
                        "Value": str(val.value())[:120],
                        "Type":  val.value_type_as_string(),
                    })
                for sub in key.subkeys():
                    rows.append({
                        "Name":  f"[SUBKEY] {sub.name()}",
                        "Value": f"{sub.subkeys_number()} subkeys / {sub.values_number()} values",
                        "Type":  "KEY",
                    })
                if rows:
                    print(c(f"\n  ── {label} ──", Fore.CYAN if HAS_COLOR else ""))
                    _print_table(rows, ["Name", "Value", "Type"])
                    all_results[label] = rows
            except Exception:
                continue
        return all_results


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 7 – USB / Removable Device History
# ══════════════════════════════════════════════════════════════════════════════
class USBForensics:
    """Extract USB and removable device history."""

    USB_KEYS = {
        "USB Storage Devices":  r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
        "USB Devices":          r"SYSTEM\CurrentControlSet\Enum\USB",
        "MountedDevices":       r"SYSTEM\MountedDevices",
        "Drive Letters":        r"SYSTEM\CurrentControlSet\Control\DeviceClasses",
        "Windows Portable Devices": r"SOFTWARE\Microsoft\Windows Portable Devices\Devices",
    }

    def run_from_hive(self, hive_path: str):
        print(c("\n[*] Extracting USB / Removable Device History...", Fore.GREEN if HAS_COLOR else ""))
        if not HAS_PYREG:
            print(c("  [-] python-registry required.", Fore.RED if HAS_COLOR else ""))
            return []
        try:
            reg = Registry.Registry(hive_path)
        except Exception as e:
            print(c(f"  [-] Cannot open hive: {e}", Fore.RED if HAS_COLOR else ""))
            return []

        all_results = {}
        for label, key_path in self.USB_KEYS.items():
            try:
                key = reg.open(key_path)
                devices = []
                for sub in key.subkeys():
                    info = {"Device Type": sub.name(), "Details": []}
                    for sub2 in sub.subkeys():
                        entry = {"ID": sub2.name(), "Values": {}}
                        for val in sub2.values():
                            entry["Values"][val.name()] = str(val.value())[:80]
                        info["Details"].append(entry)
                    devices.append(info)

                if devices:
                    print(c(f"\n  ── {label} ──", Fore.CYAN if HAS_COLOR else ""))
                    for d in devices:
                        print(c(f"    Device Class: {d['Device Type']}", Fore.WHITE if HAS_COLOR else ""))
                        for detail in d["Details"][:5]:  # limit output
                            print(f"      ID: {detail['ID']}")
                            for k, v in detail["Values"].items():
                                print(f"        {k}: {v}")
                all_results[label] = devices
            except Exception:
                continue
        return all_results


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 8 – System Information
# ══════════════════════════════════════════════════════════════════════════════
class SystemInfoExtractor:
    """Pull OS version, computer name, timezone, and install date."""

    def run_from_hive(self, hive_path: str):
        print(c("\n[*] Extracting System Information...", Fore.GREEN if HAS_COLOR else ""))
        if not HAS_PYREG:
            return {}
        try:
            reg = Registry.Registry(hive_path)
        except Exception as e:
            print(c(f"  [-] Cannot open hive: {e}", Fore.RED if HAS_COLOR else ""))
            return {}

        info = {}
        queries = {
            "OS Version":      (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", [
                                "ProductName", "ReleaseId", "CurrentBuild",
                                "CurrentVersion", "RegisteredOwner",
                                "RegisteredOrganization", "InstallDate"]),
            "Computer Name":   (r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", ["ComputerName"]),
            "Timezone":        (r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation", ["TimeZoneKeyName", "Bias"]),
            "Last Shutdown":   (r"SYSTEM\CurrentControlSet\Control\Windows", ["ShutdownTime"]),
            "Prefetch":        (r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
                                ["EnablePrefetcher"]),
            "ActiveControlSet": (r"SYSTEM\Select", ["Current", "Default", "LastKnownGood"]),
        }

        rows = []
        for section, (key_path, value_names) in queries.items():
            try:
                key = reg.open(key_path)
                for vname in value_names:
                    try:
                        val = key.value(vname)
                        raw = val.value()
                        # Convert install date (Unix timestamp) or ShutdownTime (FILETIME)
                        display = str(raw)
                        if vname == "InstallDate" and isinstance(raw, int):
                            display = datetime.fromtimestamp(raw, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                        elif vname == "ShutdownTime" and isinstance(raw, bytes) and len(raw) == 8:
                            ft = struct.unpack_from("<Q", raw)[0]
                            display = _filetime_to_dt(ft)
                        rows.append({"Section": section, "Key": vname, "Value": display})
                    except Exception:
                        pass
            except Exception:
                pass

        _print_table(rows, ["Section", "Key", "Value"])
        return rows


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 9 – Hive Dumper (via Volatility3)
# ══════════════════════════════════════════════════════════════════════════════
class HiveDumper:
    """Dump a hive from memory to disk for offline analysis."""

    def __init__(self, ctx, output_dir: str):
        self.ctx        = ctx
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def dump_all(self):
        if not HAS_VOL3:
            print(c("  [-] volatility3 required for live dump.", Fore.RED if HAS_COLOR else ""))
            return []
        print(c(f"\n[*] Dumping all hives to {self.output_dir} ...", Fore.GREEN if HAS_COLOR else ""))
        try:
            self.ctx.config["plugins.HiveDump.dump-dir"] = self.output_dir
            plugin = hivedump.HiveDump(self.ctx, config_path="plugins.HiveDump", progress_callback=None)
            dumped = []
            for hive in plugin.run():
                print(f"  [+] Dumped: {hive}")
                dumped.append(str(hive))
            return dumped
        except Exception as e:
            print(c(f"  [-] HiveDump error: {e}", Fore.RED if HAS_COLOR else ""))
            return []


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 10 – Report Generator
# ══════════════════════════════════════════════════════════════════════════════
class ReportGenerator:
    """Export all findings to JSON, CSV, or HTML."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.report = {
            "metadata": {
                "tool":      "WinRegForensics",
                "generated": datetime.utcnow().isoformat(),
            },
            "findings": {}
        }

    def add_section(self, name: str, data):
        self.report["findings"][name] = data

    def save_json(self):
        path = os.path.join(self.output_dir, "report.json")
        with open(path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(c(f"  [+] JSON report: {path}", Fore.GREEN if HAS_COLOR else ""))

    def save_csv(self):
        for section, rows in self.report["findings"].items():
            if not isinstance(rows, list) or not rows:
                continue
            safe_name = section.replace(" ", "_").replace("/", "-")
            path = os.path.join(self.output_dir, f"{safe_name}.csv")
            keys = list(rows[0].keys())
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(rows)
        print(c(f"  [+] CSV reports saved to: {self.output_dir}", Fore.GREEN if HAS_COLOR else ""))

    def save_html(self):
        path = os.path.join(self.output_dir, "report.html")
        html = [
            "<html><head><style>",
            "body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:20px}",
            "h1{color:#4fc1ff} h2{color:#9cdcfe;border-bottom:1px solid #555;padding-bottom:4px}",
            "table{border-collapse:collapse;width:100%;margin-bottom:30px}",
            "th{background:#007acc;color:#fff;padding:6px 10px;text-align:left}",
            "td{padding:5px 10px;border-bottom:1px solid #333}",
            "tr:hover{background:#2a2a2a}",
            ".meta{color:#888;font-size:0.85em;margin-bottom:20px}",
            "</style></head><body>",
            "<h1>🔍 WinRegForensics Report</h1>",
            f"<div class='meta'>Generated: {self.report['metadata']['generated']}</div>",
        ]
        for section, rows in self.report["findings"].items():
            html.append(f"<h2>{section}</h2>")
            if isinstance(rows, list) and rows:
                html.append("<table><thead><tr>")
                for k in rows[0].keys():
                    html.append(f"<th>{k}</th>")
                html.append("</tr></thead><tbody>")
                for row in rows:
                    html.append("<tr>")
                    for v in row.values():
                        html.append(f"<td>{v}</td>")
                    html.append("</tr>")
                html.append("</tbody></table>")
            else:
                html.append(f"<pre>{json.dumps(rows, indent=2, default=str)}</pre>")
        html.append("</body></html>")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        print(c(f"  [+] HTML report: {path}", Fore.GREEN if HAS_COLOR else ""))


# ══════════════════════════════════════════════════════════════════════════════
#  Utilities
# ══════════════════════════════════════════════════════════════════════════════
def _filetime_to_dt(ft: int) -> str:
    """Convert Windows FILETIME (100-ns intervals since 1601) to ISO string."""
    try:
        if not ft or ft == 0:
            return "N/A"
        timestamp = (ft - 116444736000000000) / 10000000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"

def _format_value(v) -> str:
    try:
        return str(v.Data)[:100]
    except Exception:
        return "N/A"

def _print_table(rows: list, cols: list):
    if not rows:
        print(c("  (no results)", Fore.YELLOW if HAS_COLOR else ""))
        return
    if HAS_TABULATE:
        print(tabulate([{c_: r.get(c_, "") for c_ in cols} for r in rows],
                       headers="keys", tablefmt="fancy_grid", maxcolwidths=60))
    else:
        header = " | ".join(f"{c_:<20}" for c_ in cols)
        print(header)
        print("-" * len(header))
        for row in rows:
            print(" | ".join(f"{str(row.get(c_, '')):<20}" for c_ in cols))
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  CLI Entry Point
# ══════════════════════════════════════════════════════════════════════════════
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="WinRegForensics – Windows Registry Memory Forensics Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Full analysis from a memory dump (requires volatility3):
  python regforensics.py --mem /evidence/mem.raw --all

  # Analyze a dumped hive file (no memory dump needed):
  python regforensics.py --hive SOFTWARE.hive --persistence --userassist --network --sysinfo

  # Parse SAM database from dumped hives:
  python regforensics.py --sam SAM.hive --system SYSTEM.hive

  # USB forensics from SYSTEM hive:
  python regforensics.py --hive SYSTEM.hive --usb

  # Full offline analysis with HTML report:
  python regforensics.py --hive SOFTWARE.hive --sam SAM.hive --system SYSTEM.hive --all --report-dir ./output --html
        """
    )

    # Input
    inp = parser.add_argument_group("Input")
    inp.add_argument("--mem",    metavar="FILE",  help="Path to raw memory dump (.raw/.vmem/.mem)")
    inp.add_argument("--hive",   metavar="FILE",  help="Path to extracted registry hive file")
    inp.add_argument("--sam",    metavar="FILE",  help="Path to extracted SAM hive")
    inp.add_argument("--system", metavar="FILE",  help="Path to SYSTEM hive (for syskey extraction)")

    # Modules
    mods = parser.add_argument_group("Analysis Modules")
    mods.add_argument("--all",         action="store_true", help="Run all applicable modules")
    mods.add_argument("--hives",       action="store_true", help="List all loaded hives from memory")
    mods.add_argument("--dump-hives",  action="store_true", help="Dump all hives to disk (requires --mem)")
    mods.add_argument("--sam-parse",   action="store_true", help="Parse SAM database (requires --sam)")
    mods.add_argument("--persistence", action="store_true", help="Scan persistence mechanisms")
    mods.add_argument("--userassist",  action="store_true", help="Decode UserAssist execution history")
    mods.add_argument("--network",     action="store_true", help="Network forensics artifacts")
    mods.add_argument("--usb",         action="store_true", help="USB device history")
    mods.add_argument("--sysinfo",     action="store_true", help="System information")
    mods.add_argument("--printkey",    metavar="KEY",       help="Print specific registry key (requires --mem + --offset)")
    mods.add_argument("--offset",      metavar="HEX",       help="Hive offset for --printkey")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("--report-dir", metavar="DIR",  default="./regforensics_output", help="Output directory")
    out.add_argument("--json",        action="store_true", help="Save JSON report")
    out.add_argument("--csv",         action="store_true", help="Save CSV reports")
    out.add_argument("--html",        action="store_true", help="Save HTML report")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    report = ReportGenerator(args.report_dir)
    ctx    = None

    # Build vol3 context if memory dump provided
    if args.mem:
        try:
            print(c(f"[*] Loading memory image: {args.mem}", Fore.CYAN if HAS_COLOR else ""))
            ctx = build_vol3_context(args.mem)
        except Exception as e:
            print(c(f"[-] Failed to load memory image: {e}", Fore.RED if HAS_COLOR else ""))

    # ── Hive listing ─────────────────────────────────────────────────────────
    if (args.hives or args.all) and ctx:
        r = HiveEnumerator(ctx).run()
        report.add_section("Hive List", r)

    # ── Dump hives ───────────────────────────────────────────────────────────
    if args.dump_hives and ctx:
        r = HiveDumper(ctx, args.report_dir).dump_all()
        report.add_section("Dumped Hives", [{"Path": p} for p in r])

    # ── SAM parsing ──────────────────────────────────────────────────────────
    if (args.sam_parse or args.all) and args.sam:
        r = SAMParser(args.sam, args.system).run()
        report.add_section("SAM Accounts", r)

    # ── Hive-based modules ───────────────────────────────────────────────────
    hive_path = args.hive

    if hive_path:
        if args.persistence or args.all:
            r = PersistenceAnalyzer().run_from_hive(hive_path)
            report.add_section("Persistence", r)

        if args.userassist or args.all:
            r = UserAssistAnalyzer().run_from_hive(hive_path)
            report.add_section("UserAssist", r)

        if args.network or args.all:
            r = NetworkForensics().run_from_hive(hive_path)
            report.add_section("Network", r)

        if args.usb or args.all:
            r = USBForensics().run_from_hive(hive_path)
            report.add_section("USB Devices", r)

        if args.sysinfo or args.all:
            r = SystemInfoExtractor().run_from_hive(hive_path)
            report.add_section("System Info", r)

    # ── PrintKey ─────────────────────────────────────────────────────────────
    if args.printkey and ctx:
        off = int(args.offset, 16) if args.offset else 0
        r = RegistryKeyBrowser(ctx).print_key(off, args.printkey)
        report.add_section("PrintKey", r)

    # ── Save reports ─────────────────────────────────────────────────────────
    print()
    if args.json or args.all:
        report.save_json()
    if args.csv:
        report.save_csv()
    if args.html or args.all:
        report.save_html()

    print(c("\n[✓] Analysis complete.\n", Fore.GREEN if HAS_COLOR else ""))


if __name__ == "__main__":
    main()
