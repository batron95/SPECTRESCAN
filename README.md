![GUI](https://github.com/user-attachments/assets/d8b157f5-5469-4aea-ad07-fbf388073d74)


# SpecterScan (Scan‑Only, Passive)

A PyQt5-based Wi‑Fi auditing GUI for **authorized** assessments. It uses `airmon-ng` to enable monitor mode and `Scapy` to passively sniff **beacons** and **probe responses**. No deauth, no cracking, no injection.

> ⚖️ **Legal/ethical**: Use only on networks you own or have explicit written permission to assess.

## Features
- Passive AP discovery (SSID, BSSID, channel, RSSI, encryption guess, vendor)
- Channel hopping across 2.4GHz & common 5GHz channels
- Live table with filter and CSV export
- Simple monitor mode toggling via `airmon-ng`

## Requirements
- Linux
- Python 3.8+
- Wireless adapter that supports **monitor mode**
- Packages: `aircrack-ng`, `iw`, `pyqt5`, `scapy`

## Install
```bash
sudo apt update && sudo apt install -y aircrack-ng iw python3-pip
pip3 install -r requirements.txt
```

## Run
```bash
sudo python3 SpecterScan.py
```

## Notes
- Run as **root** to control interfaces and sniff 802.11 management frames.
- On some systems, `airmon-ng` creates an interface named like `wlan0mon`. The app tries to detect and switch to it automatically.
- Channel control for 6 GHz is not included by default; extend the channel list in `ChannelHopper` if needed.

## Roadmap (passive only)
- Rogue AP detection (allowlist of approved BSSIDs/SSIDs)
- Survey logging with GPS (NMEA) and PCAP/CSV output
- HTML/PDF reporting
- Band-aware hop profiles (2.4/5/6 GHz)
