import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading
import matplotlib.pyplot as plt

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Full-Fledged Packet Sniffer")
        
        # Initialize packet counters
        self.packet_count = 0
        self.protocol_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0}

        # Create a text area for displaying packet information
        self.text_area = scrolledtext.ScrolledText(root, width=60, height=20)
        self.text_area.pack(padx=10, pady=10)

        # Create buttons for controlling sniffing and displaying statistics
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(pady=5)

        self.summary_button = tk.Button(root, text="Show Summary", command=self.show_summary)
        self.summary_button.pack(pady=5)

        self.sniffing = False

    def process_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if packet.haslayer('ICMP') else "Other"
            
            # Update counters
            self.packet_count += 1
            if protocol in self.protocol_count:
                self.protocol_count[protocol] += 1
            
            packet_info = f"Packet Size: {len(packet)} bytes\n"
            packet_info += f"Source IP: {ip_layer.src}\n"
            packet_info += f"Destination IP: {ip_layer.dst}\n"
            packet_info += f"Protocol: {protocol}\n"
            packet_info += "-" * 40 + "\n"

            # Insert packet info into the text area
            self.text_area.insert(tk.END, packet_info)
            self.text_area.yview(tk.END)  # Scroll to the end

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            threading.Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        self.sniffing = False

    def show_summary(self):
        total_packets = sum(self.protocol_count.values())
        
        if total_packets == 0:
            messagebox.showinfo("Summary", "No packets captured yet.")
            return
        
        protocols = list(self.protocol_count.keys())
        counts = list(self.protocol_count.values())

        plt.figure(figsize=(8, 6))
        
        # Pie chart for protocol distribution
        plt.subplot(1, 2, 1)
        plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=140)
        plt.axis('equal')
        plt.title(f"Protocol Distribution - Total Packets: {total_packets}")

        # Bar chart for protocol counts
        plt.subplot(1, 2, 2)
        plt.bar(protocols, counts)
        plt.title("Packet Count by Protocol")
        plt.xlabel("Protocols")
        plt.ylabel("Count")

        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
