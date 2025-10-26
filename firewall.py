from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
import logging
import tkinter as tk
from tkinter import scrolledtext

# Load rules
with open("rules.json") as f:
    rules = json.load(f)

logging.basicConfig(filename="firewall.log", level=logging.INFO)

# Optional GUI
root = tk.Tk()
root.title("Personal Firewall")
log_window = scrolledtext.ScrolledText(root, width=80, height=20)
log_window.pack()

def update_gui(packet_summary):
    log_window.insert(tk.END, packet_summary + "\n")
    log_window.yview(tk.END)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in rules["block_ips"] or dst_ip in rules["block_ips"]:
            logging.info(f"Blocked packet: {packet.summary()}")
            update_gui(f"Blocked: {packet.summary()}")
            return

        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport
            allowed_ports = rules.get("allow_ports", [])
            if allowed_ports and sport not in allowed_ports and dport not in allowed_ports:
                logging.info(f"Blocked packet due to port: {packet.summary()}")
                update_gui(f"Blocked Port: {packet.summary()}")
                return

        if ICMP in packet and "ICMP" in rules.get("block_protocols", []):
            logging.info(f"Blocked ICMP packet: {packet.summary()}")
            update_gui(f"Blocked ICMP: {packet.summary()}")
            return

        update_gui(f"Allowed: {packet.summary()}")

# Run packet sniffing in background
import threading
t = threading.Thread(target=lambda: sniff(prn=packet_callback, store=0))
t.daemon = True
t.start()

root.mainloop()