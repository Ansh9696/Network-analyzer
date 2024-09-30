import tkinter as tk
from tkinter import scrolledtext, messagebox, font
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("800x600")
        self.root.config(bg="#2E2E2E")

        # Custom font
        self.custom_font = font.Font(family="Arial", size=10)

        # Instructions
        tk.Label(root, text="Network Packet Analyzer", font=('Arial', 20), bg="#2E2E2E", fg="white").pack(pady=10)
        tk.Label(root, text="Captures and analyzes network packets.", font=self.custom_font, bg="#2E2E2E", fg="lightgray").pack(pady=5)

        # Display area for packet information
        self.display_area = scrolledtext.ScrolledText(root, height=20, width=100, state=tk.DISABLED, bg="#1E1E1E", fg="white", font=self.custom_font)
        self.display_area.pack(pady=10)

        # Buttons for starting and stopping sniffing
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing, bg="#4CAF50", fg="white", font=self.custom_font)
        self.start_button.pack(side=tk.LEFT, padx=(20, 10), pady=10)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, bg="#F44336", fg="white", font=self.custom_font, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(10, 20), pady=10)

        self.sniffer_thread = None
        self.sniffing = False

    def capture_packets(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            # Identify protocol
            if protocol == 6:
                proto = "TCP"
            elif protocol == 17:
                proto = "UDP"
            elif protocol == 1:
                proto = "ICMP"
            else:
                proto = "Other"

            # Get payload as hex
            payload = bytes(packet).hex()
            packet_info = (f"Source: {src_ip}\nDestination: {dst_ip}\nProtocol: {proto}\n"
                           f"Payload: {payload[:50]}...\n{'-'*80}\n")

            # Update display area
            self.update_display(packet_info)

    def update_display(self, packet_info):
        self.display_area.config(state=tk.NORMAL)
        self.display_area.insert(tk.END, packet_info)
        self.display_area.see(tk.END)  # Scroll to the end
        self.display_area.config(state=tk.DISABLED)

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        try:
            sniff(prn=self.capture_packets, store=False, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            self.update_display(f"Error: {str(e)}\n")
            self.stop_sniffing()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
