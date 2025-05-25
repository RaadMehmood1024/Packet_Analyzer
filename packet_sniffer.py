import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    proto = packet.sprintf("%IP.proto%")
    sport = packet[IP].sport if hasattr(packet[IP], 'sport') else "N/A"
    dport = packet[IP].dport if hasattr(packet[IP], 'dport') else "N/A"

    if protocol_filter.get() != "Any" and protocol_filter.get().upper() != proto:
        return

    if port_filter.get():
        try:
            port = int(port_filter.get())
            if port != sport and port != dport:
                return
        except ValueError:
            return

    info = f"Src: {packet[IP].src} -> Dst: {packet[IP].dst} | Proto: {proto} | Sport: {sport} | Dport: {dport}\n"
    output_text.insert(tk.END, info)
    output_text.see(tk.END)

def start_sniffing():
    output_text.delete(1.0, tk.END)
    threading.Thread(target=lambda: sniff(prn=packet_callback, store=False), daemon=True).start()

# GUI Setup
root = tk.Tk()
root.title("Network Packet Analyzer")

frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(frame, text="Protocol Filter:").grid(row=0, column=0, sticky="w")
protocol_filter = ttk.Combobox(frame, values=["Any", "TCP", "UDP", "ICMP"])
protocol_filter.set("Any")
protocol_filter.grid(row=0, column=1, sticky="ew", padx=5)

ttk.Label(frame, text="Port Filter:").grid(row=1, column=0, sticky="w")
port_filter = ttk.Entry(frame)
port_filter.grid(row=1, column=1, sticky="ew", padx=5)

start_button = ttk.Button(frame, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=2, column=0, columnspan=2, pady=5)

output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=20)
output_text.grid(row=3, column=0, columnspan=2, pady=10)

root.mainloop()
