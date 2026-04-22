# WinRegForensics 🔍
**Windows Registry Memory Forensics Tool**

A Python tool for performing comprehensive Windows registry forensics from memory dumps or extracted hive files. Built for digital forensics students and practitioners.

---

## Features

| Module | Description |
|--------|-------------|
| **Hive Enumeration** | List all loaded registry hives from a memory dump |
| **Hive Dumping** | Extract hive files to disk from a live memory image |
| **SAM Database** | Parse user accounts and extract NT/LM password hashes |
| **Persistence** | Scan 15+ common autorun/persistence registry locations |
| **UserAssist** | Decode ROT-13 program execution history (MRU) |
| **Network Forensics** | Wi-Fi profiles, mapped drives, typed URLs, RDP history |
| **USB Forensics** | Enumerate connected USB/removable device history |
| **System Info** | OS version, computer name, timezone, install date, last shutdown |
| **Key Browser** | Browse any specific key/value in a live memory image |
| **Report Export** | JSON, CSV, and HTML report generation |
| **RecentDocs (Module 11)** | Extract recently accessed files (MRU artifacts) |
| **Installed Programs (Module 12)** | Enumerate installed software & uninstall history |

---

## Installation

```bash
pip install -r requirements.txt
```

### Volatility3 Symbol Tables
For memory dump analysis you also need Windows symbol tables:
```bash
# Download from: https://downloads.volatilityfoundation.org/volatility3/symbols/
# Place .zip files in: volatility3/symbols/windows/
```

---

## Usage

### 1. Full Analysis from Memory Dump
```bash
python regforensics.py --mem /evidence/win10.raw --all --html
```

### 2. List All Hives in Memory
```bash
python regforensics.py --mem /evidence/win10.raw --hives
```

### 3. Dump All Hives to Disk
```bash
python regforensics.py --mem /evidence/win10.raw --dump-hives --report-dir ./dumped_hives
```

### 4. Parse SAM Database (after dumping hives)
```bash
python regforensics.py --sam ./dumped_hives/SAM --system ./dumped_hives/SYSTEM --sam-parse
```

### 5. Persistence + UserAssist on Offline Hive
```bash
python regforensics.py --hive SOFTWARE --persistence --userassist
```

### 6. Network Forensics
```bash
python regforensics.py --hive SOFTWARE --hive SYSTEM --network
```

### 7. USB Device History
```bash
python regforensics.py --hive SYSTEM --usb
```

### 8. Browse a Specific Registry Key
```bash
python regforensics.py --mem /evidence/win10.raw --offset 0xffff8f01 \
  --printkey "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### 9. Full Offline Analysis with All Reports
```bash
python regforensics.py \
  --hive SOFTWARE \
  --sam SAM \
  --system SYSTEM \
  --all \
  --report-dir ./case_001 \
  --json --csv --html
```

---

## Typical Workflow (Memory Dump → Full Report)

```
1. Acquire memory image (WinPmem, FTK Imager, etc.)
2. Run: python regforensics.py --mem image.raw --hives
3. Run: python regforensics.py --mem image.raw --dump-hives --report-dir ./hives
4. Run: python regforensics.py --hive ./hives/SOFTWARE --all
5. Run: python regforensics.py --sam ./hives/SAM --system ./hives/SYSTEM --sam-parse
6. Review HTML report in ./regforensics_output/report.html
```

---

## Module-Specific Examples

# Recently accessed files from NTUSER.DAT:
  python regforensics.py --hive registry.NTUSERDAT.hive --recentdocs

  # Installed programs from SOFTWARE hive:
  python regforensics.py --hive registry.SOFTWARE.hive --installed

---

## Key Registry Locations Covered

### Persistence
- `...\CurrentVersion\Run` / `RunOnce`
- `Winlogon` (shell, userinit)
- `AppInit_DLLs`
- `BootExecute`
- `Image File Execution Options` (debugger hijacking)
- `Services`

### Network
- DHCP/Static IP configuration
- Wi-Fi SSID profiles
- Mapped network drives
- RDP (Terminal Server Client) server history
- Typed URLs (Internet Explorer)

### User Activity
- UserAssist (ROT-13 decoded execution history with run count & timestamps)
- OpenSaveMRU dialog history

### USB
- USBSTOR device class entries (VID/PID, serial number)
- MountedDevices (drive letter ↔ device mapping)

---

## Output Formats

| Format | File | Contents |
|--------|------|----------|
| JSON   | `report.json` | Full structured findings |
| CSV    | `<section>.csv` per module | Flat tables |
| HTML   | `report.html` | Dark-theme interactive report |

---

## Dependencies

- **volatility3** – Memory image parsing (live dump analysis)
- **python-registry** – Offline hive file parsing
- **tabulate** – Terminal table formatting
- **colorama** – Colored terminal output

---
## Why WinRegForensics over Volatility3?

| Feature | WinRegForensics | Volatility3 |
|---|---|---|
| Purpose | Registry-focused forensics | General memory forensics |
| ease of use | Single command per module | Complex plugin syntax |
| Output | Formatted tables | Raw text output |
| Reports | HTML, JSON, CSV built-in | No built-in reporting |
| Registry Modules | 10 dedicated modules | Generic registry plugins |
| UserAssist Decoding | ROT-13 auto-decoded | Manual decoding needed |
| USB Forensics | Dedicated module | No dedicated plugin |
| Persistence Detection | Dedicated module | No dedicated plugin |
| SAM Parser | Built-in | Requires separate plugin |
| Network Artifacts | Dedicated module | No dedicated plugin |
| Offline Hive Analysis | Yes | No |
| Symbol Setup | Auto-handled | Manual setup required |
| Learning Curve | Beginner friendly | Advanced users |
| Memory + Hive | Both supported | Memory only |
| Platform | Windows focused | Cross-platform |


---
## Legal Notice

> This tool is intended **exclusively** for authorized forensic investigations,
> academic research, and CTF challenges. Only analyze systems and memory images
> you own or have explicit written permission to examine. Unauthorized access
> to computer systems is illegal.
