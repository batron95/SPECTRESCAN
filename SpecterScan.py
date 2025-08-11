#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SpecterScan (Scan-Only) — Dark Theme Edition
# Passive Wi‑Fi auditor GUI (PyQt5 + Scapy). Linux only.
#
# Install:
#   sudo apt update && sudo apt install -y aircrack-ng iw python3-pip
#   pip3 install pyqt5 scapy
#
# Run:
#   sudo python3 SpecterScan.py
#
import sys
import os
import re
import csv
import time
import signal
import subprocess
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple

from PyQt5 import QtCore, QtGui, QtWidgets
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap

APP_TITLE = "SPECTERSCAN — Passive Wi‑Fi Auditor"

# --------------------------- Helpers & Models --------------------------- #

def require_root():
    if os.geteuid() != 0:
        QtWidgets.QMessageBox.critical(None, "Root required",
                                       "Please run this program with sudo/root.")
        sys.exit(1)

def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(timeout=10)
        return p.returncode, out.strip(), err.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"

def list_wireless_ifaces() -> List[str]:
    code, out, _ = run_cmd(["iw", "dev"])
    if code == 0:
        ifaces = re.findall(r"Interface\s+([^\s]+)", out)
        return sorted(set(ifaces))
    code, out, _ = run_cmd(["airmon-ng"])
    if code == 0:
        m = re.findall(r"(?m)^(w[a-z0-9]+)", out)
        return sorted(set(m))
    return []

def guess_vendor_from_bssid(bssid: str) -> str:
    OUI = {
        "00:11:22": "Cisco",
        "00:17:9A": "Apple",
        "00:1A:1E": "Netgear",
        "00:1D:7E": "Ubiquiti",
        "00:1F:3A": "D-Link",
        "F4:F5:E8": "TP-Link",
        "C8:D7:19": "ASUS",
        "B8:27:EB": "Raspberry Pi",
        "3C:84:6A": "Cisco",
        "DC:A6:32": "Aruba",
    }
    pref = bssid.upper()[0:8]
    return OUI.get(pref, "")

def elt_value(pkt, elt_id):
    elts = pkt.getlayer(Dot11Elt)
    while isinstance(elts, Dot11Elt):
        if elts.ID == elt_id:
            return elts.info
        elts = elts.payload.getlayer(Dot11Elt)
    return None

def parse_channel(pkt) -> Optional[int]:
    ds = elt_value(pkt, 3)
    if ds and len(ds) == 1:
        return ds[0]
    return None

def parse_encryption(pkt) -> str:
    enc = "OPEN"
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        caps = pkt[Dot11Beacon].cap if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp].cap
        privacy = bool(caps & 0x10)
        rsn = elt_value(pkt, 48)   # RSN
        wpa = None
        elts = pkt.getlayer(Dot11Elt)
        while isinstance(elts, Dot11Elt):
            if elts.ID == 221 and elts.info and len(elts.info) >= 4:
                if elts.info[0:3] == b'\x00\x50\xf2' and elts.info[3] == 1:
                    wpa = elts.info
                    break
            elts = elts.payload.getlayer(Dot11Elt)
        if privacy:
            if rsn:
                enc = "WPA2/3"
            elif wpa:
                enc = "WPA"
            else:
                enc = "WEP?"
    return enc

def get_rssi(pkt) -> Optional[int]:
    try:
        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal"):
            return int(pkt[RadioTap].dBm_AntSignal)
    except Exception:
        pass
    return None

@dataclass
class APRecord:
    ssid: str
    bssid: str
    channel: Optional[int] = None
    encryption: str = "OPEN"
    vendor: str = ""
    beacons: int = 0
    last_rssi: Optional[int] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_row(self):
        return [
            self.ssid if self.ssid else "<hidden>",
            self.bssid,
            str(self.channel) if self.channel is not None else "",
            self.encryption,
            str(self.last_rssi) if self.last_rssi is not None else "",
            self.vendor,
            datetime.fromtimestamp(self.first_seen).strftime("%H:%M:%S"),
            datetime.fromtimestamp(self.last_seen).strftime("%H:%M:%S"),
            str(self.beacons),
        ]

# --------------------------- Sniffer & Hopper --------------------------- #

class ChannelHopper(QtCore.QObject):
    finished = QtCore.pyqtSignal()

    def __init__(self, iface: str, parent=None):
        super().__init__(parent)
        self.iface = iface

    @QtCore.pyqtSlot()
    def run(self):
        channels_24 = list(range(1, 14))
        channels_5 = [36, 40, 44, 48, 149, 153, 157, 161]
        hop_list = channels_24 + channels_5
        i = 0
        while not QtCore.QThread.currentThread().isInterruptionRequested():
            ch = hop_list[i % len(hop_list)]
            run_cmd(["iw", "dev", self.iface, "set", "channel", str(ch)])
            i += 1
            QtCore.QThread.msleep(180)
        self.finished.emit()

class Sniffer(QtCore.QThread):
    ap_updated = QtCore.pyqtSignal()

    def __init__(self, iface: str, chan_hop: bool = True, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.chan_hop = chan_hop
        self.running = False
        self.ap_map: Dict[str, APRecord] = {}
        self._hop_thread = None

    def run(self):
        self.running = True
        if self.chan_hop:
            self._hop_thread = QtCore.QThread()
            hopper = ChannelHopper(self.iface)
            hopper.moveToThread(self._hop_thread)
            self._hop_thread.started.connect(hopper.run)
            hopper.finished.connect(self._hop_thread.quit)
            hopper.finished.connect(hopper.deleteLater)
            self._hop_thread.start()
        try:
            sniff(
                iface=self.iface,
                prn=self._handle,
                store=False,
                stop_filter=lambda x: not self.running,
                monitor=True
            )
        except Exception as e:
            print(f"[!] Sniff error: {e}")
        self.running = False
        if self._hop_thread and self._hop_thread.isRunning():
            self._hop_thread.requestInterruption()
            self._hop_thread.quit()
            self._hop_thread.wait()

    def stop(self):
        self.running = False

    def _handle(self, pkt):
        if not pkt.haslayer(Dot11):
            return
        if pkt.type != 0 or pkt.subtype not in (8, 5):
            return

        bssid = pkt[Dot11].addr2
        if not bssid:
            return

        ssid = elt_value(pkt, 0) or b""
        try:
            ssid = ssid.decode(errors="ignore")
        except Exception:
            ssid = ""

        ch = parse_channel(pkt)
        enc = parse_encryption(pkt)
        rssi = get_rssi(pkt)

        if bssid not in self.ap_map:
            vendor = guess_vendor_from_bssid(bssid)
            self.ap_map[bssid] = APRecord(
                ssid=ssid,
                bssid=bssid,
                channel=ch,
                encryption=enc,
                vendor=vendor,
                beacons=1,
                last_rssi=rssi
            )
        else:
            rec = self.ap_map[bssid]
            rec.ssid = ssid or rec.ssid
            rec.channel = ch if ch is not None else rec.channel
            rec.encryption = enc or rec.encryption
            rec.last_rssi = rssi if rssi is not None else rec.last_rssi
            rec.last_seen = time.time()
            rec.beacons += 1

        if int(time.time() * 10) % 5 == 0:
            self.ap_updated.emit()

# --------------------------- GUI --------------------------- #

DARK_QSS = """
/* Root */
QWidget {
    background-color: #0b0b0d;
    color: #e3e3e3;
    font-family: 'Consolas', 'Fira Code', 'DejaVu Sans Mono', monospace;
    font-size: 12px;
}

/* Banner */
#Banner {
    background-color: #1a0003;
    border: 1px solid #990000;
    padding: 10px;
}

#TitleLabel {
    color: #ff2e2e;
    font-size: 28px;
    font-weight: 900;
    letter-spacing: 1px;
}

#SubLabel {
    color: #b35252;
    font-size: 12px;
}

/* Controls */
QComboBox, QLineEdit {
    background-color: #121214;
    border: 1px solid #552222;
    padding: 6px;
    selection-background-color: #ff2e2e;
    selection-color: #000;
}

QPushButton {
    background-color: rgba(255, 46, 46, 0.08);
    border: 1px solid #7a1c1c;
    padding: 6px 10px;
    color: #ffb3b3;
}
QPushButton:hover {
    background-color: rgba(255, 46, 46, 0.18);
}
QPushButton:pressed {
    background-color: rgba(255, 46, 46, 0.28);
}
QPushButton[destructive=\"true\"] {
    color: #ffdada;
    border: 1px solid #b30000;
}

/* Table */
QHeaderView::section {
    background-color: #1a0c0c;
    color: #ffbcbc;
    border: 1px solid #552222;
    padding: 6px;
    font-weight: 700;
}
QTableView {
    gridline-color: #331111;
    alternate-background-color: #101012;
    selection-background-color: #7a1c1c;
    selection-color: #fff;
    border: 1px solid #331111;
}
"""

class APTableModel(QtCore.QAbstractTableModel):
    HEADERS = ["SSID", "BSSID", "Ch", "Enc", "RSSI", "Vendor", "First Seen", "Last Seen", "Beacons"]

    def __init__(self, sniffer: Sniffer, parent=None):
        super().__init__(parent)
        self.sniffer = sniffer
        self.rows: List[APRecord] = []
        self.filter_text = ""

    def rowCount(self, parent=None): return len(self.rows)
    def columnCount(self, parent=None): return len(self.HEADERS)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid(): return None
        rec = self.rows[index.row()]
        if role == QtCore.Qt.DisplayRole:
            return rec.to_row()[index.column()]
        if role == QtCore.Qt.TextAlignmentRole:
            return QtCore.Qt.AlignCenter
        if role == QtCore.Qt.ForegroundRole and index.column() == 3:
            if rec.encryption.startswith("OPEN"):
                return QtGui.QBrush(QtGui.QColor("#ff6b57"))
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole: return None
        if orientation == QtCore.Qt.Horizontal:
            return self.HEADERS[section]
        return section + 1

    def refresh(self):
        all_rows = list(self.sniffer.ap_map.values())
        if self.filter_text:
            f = self.filter_text.lower()
            self.rows = [r for r in all_rows if f in (r.ssid or "").lower() or f in r.bssid.lower()]
        else:
            self.rows = all_rows
        self.rows.sort(key=lambda r: (-(r.last_rssi or -999), r.ssid))
        self.layoutChanged.emit()

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setMinimumSize(1100, 620)
        self.setStyleSheet(DARK_QSS)

        self.sniffer: Optional[Sniffer] = None
        self.monitor_iface_name = None

        # Banner
        self.banner = QtWidgets.QWidget(objectName="Banner")
        title = QtWidgets.QLabel("BLOOD‑RED SPECTERSCAN", objectName="TitleLabel")
        subtitle = QtWidgets.QLabel("Passive Wi‑Fi Recon Dashboard — Authorized Use Only", objectName="SubLabel")
        b_lay = QtWidgets.QVBoxLayout(self.banner)
        b_lay.addWidget(title)
        b_lay.addWidget(subtitle)

        # Controls
        self.iface_combo = QtWidgets.QComboBox()
        self.refresh_ifaces_btn = QtWidgets.QPushButton("Refresh")
        self.toggle_monitor_btn = QtWidgets.QPushButton("Enable Monitor")
        self.toggle_monitor_btn.setProperty("destructive", True)
        self.start_btn = QtWidgets.QPushButton("Start")
        self.stop_btn = QtWidgets.QPushButton("Stop"); self.stop_btn.setEnabled(False)
        self.filter_edit = QtWidgets.QLineEdit(); self.filter_edit.setPlaceholderText("Filter SSID/BSSID…")
        self.export_btn = QtWidgets.QPushButton("Export CSV")

        top = QtWidgets.QHBoxLayout()
        for w in (QtWidgets.QLabel("Interface:"), self.iface_combo, self.refresh_ifaces_btn,
                  self.toggle_monitor_btn, self.start_btn, self.stop_btn,
                  self.filter_edit, self.export_btn):
            top.addWidget(w)
        top.setSpacing(10)

        # Table
        self.model = APTableModel(None)
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(False)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.table.setAlternatingRowColors(True)

        central = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(central)
        v.addWidget(self.banner)
        v.addLayout(top)
        v.addWidget(self.table)
        self.setCentralWidget(central)

        # Signals
        self.refresh_ifaces_btn.clicked.connect(self.load_ifaces)
        self.toggle_monitor_btn.clicked.connect(self.toggle_monitor_mode)
        self.start_btn.clicked.connect(self.start_sniff)
        self.stop_btn.clicked.connect(self.stop_sniff)
        self.filter_edit.textChanged.connect(self.on_filter)
        self.export_btn.clicked.connect(self.export_csv)

        self.load_ifaces()

    # ---------------- Interface & Monitor Mode ---------------- #
    def load_ifaces(self):
        self.iface_combo.clear()
        ifaces = list_wireless_ifaces()
        if not ifaces:
            QtWidgets.QMessageBox.warning(self, "No interfaces", "No wireless interfaces found.")
        else:
            self.iface_combo.addItems(ifaces)

    def toggle_monitor_mode(self):
        iface = self.iface_combo.currentText()
        if not iface:
            QtWidgets.QMessageBox.warning(self, "Select interface", "Pick a wireless interface first.")
            return
        if not self.monitor_iface_name:
            code, out, err = run_cmd(["airmon-ng", "start", iface])
            mon = re.search(r"monitor mode vif enabled.*\[(.+?)\]", out + "\n" + err, re.IGNORECASE)
            self.monitor_iface_name = mon.group(1) if mon else iface + "mon"
            QtWidgets.QMessageBox.information(self, "Monitor Mode",
                                              f"Tried enabling monitor mode.\nstdout:\n{out}\n\nstderr:\n{err}")
            self.toggle_monitor_btn.setText("Disable Monitor")
            if self.monitor_iface_name not in [self.iface_combo.itemText(i) for i in range(self.iface_combo.count())]:
                self.iface_combo.addItem(self.monitor_iface_name)
            self.iface_combo.setCurrentText(self.monitor_iface_name)
        else:
            code, out, err = run_cmd(["airmon-ng", "stop", self.monitor_iface_name])
            QtWidgets.QMessageBox.information(self, "Monitor Mode",
                                              f"Tried disabling monitor mode.\nstdout:\n{out}\n\nstderr:\n{err}")
            self.toggle_monitor_btn.setText("Enable Monitor")
            self.monitor_iface_name = None
            self.load_ifaces()

    # ---------------- Sniff Control ---------------- #
    def start_sniff(self):
        iface = self.iface_combo.currentText()
        if not iface:
            QtWidgets.QMessageBox.warning(self, "Select interface", "Pick a wireless interface first.")
            return
        if self.sniffer and self.sniffer.running:
            return
        self.sniffer = Sniffer(iface=iface, chan_hop=True)
        self.model = APTableModel(self.sniffer)
        self.table.setModel(self.model)
        self.sniffer.ap_updated.connect(self.model.refresh)
        self.sniffer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_sniff(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            self.sniffer.wait(1500)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_filter(self, text):
        self.model.filter_text = text.strip()
        self.model.refresh()

    def export_csv(self):
        if not self.sniffer:
            QtWidgets.QMessageBox.warning(self, "No data", "Start a scan first.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export CSV", "specterscan.csv",
                                                        "CSV Files (*.csv)")
        if not path:
            return
        rows = [r.to_row() for r in self.model.rows]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(APTableModel.HEADERS)
            w.writerows(rows)
        QtWidgets.QMessageBox.information(self, "Exported", f"Saved {len(rows)} rows to {path}")

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        try:
            self.stop_sniff()
        finally:
            super().closeEvent(event)

# --------------------------- Main --------------------------- #

def main():
    require_root()
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
