import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, AsyncSniffer  # Import AsyncSniffer
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        # Create a text area for displaying packet information
        self.text_area = scrolledtext.ScrolledText(root, width=60, height=20)
        self.text_area.pack(padx=10, pady=10)

        # Create a start button to begin sniffing
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        # Create a stop button to stop sniffing
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(pady=5)

        self.sniffer = None

    def process_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            packet_info = f"Packet Size: {len(packet)} bytes\n"
            packet_info += f"Source IP: {ip_layer.src}\n"
            packet_info += f"Destination IP: {ip_layer.dst}\n"
            packet_info += f"Protocol: {ip_layer.proto}\n"
            packet_info += "-" * 40 + "\n"

            # Insert packet info into the text area
            self.text_area.insert(tk.END, packet_info)
            self.text_area.yview(tk.END)  # Scroll to the end

    def start_sniffing(self):
        if not self.sniffer:
            # Use AsyncSniffer for non-blocking sniffing
            self.sniffer = AsyncSniffer(prn=self.process_packet, store=False)
            self.sniffer.start()  # Start sniffing in a non-blocking way

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()  # Stop the sniffer
            self.sniffer = None  # Reset the sniffer reference

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
