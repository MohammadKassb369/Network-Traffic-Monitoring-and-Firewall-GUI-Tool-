# Network-Traffic-Monitoring-and-Firewall-GUI-Tool
# What It Does
# Captures Live Network Traffic
Uses Scapy to sniff IP packets on the network in real time.

Each captured packet's source IP, destination IP, and protocol are recorded.

The information is added to a shared log (traffic_data) and protocol statistics (traffic_stats).

# GUI Dashboard with Multiple Tabs
Built using PyQt5, the app has the following interactive tabs:

# GUI Tabs Breakdown
# Traffic Monitor Tab
Displays a scrollable log of captured packets (source -> destination | protocol).

Buttons:

Clear Logs: Clears current traffic history.

Export to CSV: Saves logs to a .csv file.

# Live Graph Tab
Shows a live line graph using pyqtgraph that:

Plots how many packets have been captured every few seconds.

Good for tracking traffic spikes or patterns over time.

# Protocol Graph Tab
Displays a bar graph of protocol usage distribution.

For example, if more TCP or UDP packets are seen, those bars are taller.

Helps visualize what protocols dominate the traffic.

# Metrics Explorer Tab
Analyzes and shows:

Top Talkers: IP addresses sending the most traffic.

Top Ports: Most frequently used source ports.

Helps identify suspicious or high-volume sources.

# Firewall Manager Tab
Manual Firewall-like Controls:

Block IP: Add an IP address to a blocklist.

Packets from blocked IPs are ignored.

Whitelist IPs: Prevents mistakenly blocking friendly IPs.

View both:

Blocked IPs (rules_view)

Whitelisted IPs (whitelist_view)

⚙️ How It Works Internally
✅ Packet Capture
Runs in a background thread (threading.Thread) to prevent UI freezing.

Uses scapy.sniff() with a callback to process_packet().

Only IP packets are processed.

✅ Data Sharing
Uses Python global variables like traffic_data, traffic_stats, and firewall_rules.

These are accessed and updated by all components (tabs) of the GUI.

# Technologies Used
Tool	Purpose
Scapy	Packet sniffing
PyQt5	GUI toolkit for desktop
PyQtGraph	Fast, real-time plotting
Threading	Non-blocking sniffing
CSV	Exporting logs

# Use Cases
Network diagnostics on a local machine

Detecting high traffic IPs or protocols

Manually testing simple firewall rules

Visualizing trends in real-time packet flow

Educational tool to understand network packets

# Notes
Requires admin privileges to sniff traffic on most systems (especially Windows).

Not a full firewall — more like a monitoring + filtering utility.

Not encrypted or secured — meant for local use or development/learning.


