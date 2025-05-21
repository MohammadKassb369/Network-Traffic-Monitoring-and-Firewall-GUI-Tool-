import sys
import socket
import threading
import csv
from collections import defaultdict
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QLabel, QLineEdit, QTabWidget, QMessageBox, QFileDialog, QListWidget
)
from PyQt5.QtCore import QTimer
import pyqtgraph as pg
from scapy.all import sniff, IP

traffic_data = []
traffic_stats = defaultdict(int)
firewall_rules = set()


class EnhancedTrafficTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.clear_button = QPushButton("Clear Logs")
        self.export_button = QPushButton("Export to CSV")

        self.clear_button.clicked.connect(self.clear_logs)
        self.export_button.clicked.connect(self.export_to_csv)

        layout.addWidget(self.log_output)
        layout.addWidget(self.clear_button)
        layout.addWidget(self.export_button)
        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_logs)
        self.timer.start(2000)

    def update_logs(self):
        self.log_output.clear()
        self.log_output.append("\n".join(traffic_data[-200:]))

    def clear_logs(self):
        traffic_data.clear()
        self.log_output.clear()

    def export_to_csv(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save File", "", "CSV Files (*.csv)")
        if file_name:
            with open(file_name, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Traffic Log"])
                for line in traffic_data:
                    writer.writerow([line])
            QMessageBox.information(self, "Export", "Traffic exported successfully!")


class GraphTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.graph = pg.PlotWidget(title="Live Traffic")
        self.data = []
        layout.addWidget(self.graph)
        self.setLayout(layout)

        self.ptr = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(2000)

    def update_graph(self):
        self.ptr += 1
        self.data.append(len(traffic_data))
        self.graph.clear()
        self.graph.plot(self.data[-50:], pen='g')


class ProtocolGraphTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.graph = pg.PlotWidget()
        self.graph.setTitle("Protocol Distribution")
        layout.addWidget(self.graph)
        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_chart)
        self.timer.start(3000)

    def update_chart(self):
        self.graph.clear()
        protocols = list(traffic_stats.keys())
        counts = [traffic_stats[p] for p in protocols]
        bg = pg.BarGraphItem(x=range(len(protocols)), height=counts, width=0.6, brush='b')
        self.graph.addItem(bg)
        self.graph.getAxis('bottom').setTicks([list(enumerate(protocols))])


class MetricsExplorerTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.output = QTextEdit()
        self.refresh_btn = QPushButton("Refresh Metrics")
        self.refresh_btn.clicked.connect(self.update_metrics)
        layout.addWidget(self.refresh_btn)
        layout.addWidget(self.output)
        self.setLayout(layout)

    def update_metrics(self):
        src_counter = defaultdict(int)
        port_counter = defaultdict(int)

        for line in traffic_data:
            if "->" in line:
                parts = line.split()
                src = parts[0]
                if ":" in src:
                    src_ip, src_port = src.split(":")
                    src_counter[src_ip] += 1
                    port_counter[src_port] += 1
                else:
                    src_counter[src] += 1

        top_talkers = sorted(src_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ports = sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:5]

        self.output.clear()
        self.output.append("Top Talkers:\n" + "\n".join([f"{ip}: {count}" for ip, count in top_talkers]))
        self.output.append("\nTop Ports:\n" + "\n".join([f"{port}: {count}" for port, count in top_ports]))


class EnhancedFirewallTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.rule_input = QLineEdit()
        self.rule_input.setPlaceholderText("Block IP")
        self.rule_button = QPushButton("Block IP")
        self.rule_button.clicked.connect(self.add_firewall_rule)

        self.rules_view = QTextEdit()
        self.rules_view.setReadOnly(True)

        self.whitelist = set()
        self.whitelist_input = QLineEdit()
        self.whitelist_input.setPlaceholderText("Add IP to Whitelist")
        self.whitelist_button = QPushButton("Add to Whitelist")
        self.whitelist_button.clicked.connect(self.add_to_whitelist)
        self.whitelist_view = QListWidget()

        layout.addWidget(QLabel("Firewall Manager"))
        layout.addWidget(self.rule_input)
        layout.addWidget(self.rule_button)
        layout.addWidget(QLabel("Blocked IPs"))
        layout.addWidget(self.rules_view)
        layout.addWidget(QLabel("Whitelist"))
        layout.addWidget(self.whitelist_input)
        layout.addWidget(self.whitelist_button)
        layout.addWidget(self.whitelist_view)
        self.setLayout(layout)

    def add_firewall_rule(self):
        ip = self.rule_input.text().strip()
        if ip and ip not in self.whitelist:
            firewall_rules.add(ip)
            self.rules_view.append(ip)
            QMessageBox.information(self, "Firewall", f"Blocked IP: {ip}")
        elif ip in self.whitelist:
            QMessageBox.warning(self, "Firewall", f"{ip} is whitelisted!")

    def add_to_whitelist(self):
        ip = self.whitelist_input.text().strip()
        if ip:
            self.whitelist.add(ip)
            self.whitelist_view.addItem(ip)
            QMessageBox.information(self, "Whitelist", f"Added {ip} to whitelist.")


class NetworkInspector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enhanced Network Inspector Dashboard")
        self.resize(900, 600)

        self.tabs = QTabWidget()
        self.traffic_tab = EnhancedTrafficTab()
        self.graph_tab = GraphTab()
        self.protocol_graph_tab = ProtocolGraphTab()
        self.metrics_tab = MetricsExplorerTab()
        self.firewall_tab = EnhancedFirewallTab()

        self.tabs.addTab(self.traffic_tab, "Traffic Monitor")
        self.tabs.addTab(self.graph_tab, "Live Graph")
        self.tabs.addTab(self.protocol_graph_tab, "Protocol Graph")
        self.tabs.addTab(self.metrics_tab, "Metrics Explorer")
        self.tabs.addTab(self.firewall_tab, "Firewall Manager")

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        self.setLayout(layout)
        self.start_sniffing()

    def start_sniffing(self):
        thread = threading.Thread(target=self.sniff_traffic, daemon=True)
        thread.start()

    def sniff_traffic(self):
        sniff(prn=self.process_packet, store=False, filter="ip")

    def process_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            line = f"{src} -> {dst} | Protocol: {proto}"

            if src in firewall_rules:
                return
            traffic_data.append(line)
            traffic_stats[str(proto)] += 1


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkInspector()
    window.show()
    sys.exit(app.exec_())
