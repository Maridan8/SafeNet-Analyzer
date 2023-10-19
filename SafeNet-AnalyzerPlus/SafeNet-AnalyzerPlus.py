# -*- coding: utf-8 -*-
'''
   _____       ____     _   __     __        ___                __         
  / ___/____ _/ __/__  / | / /__  / /_      /   |  ____  ____ _/ /_  ______  ___  _____   
  \__ \/ __ `/ /_/ _ \/  |/ / _ \/ __/_____/ /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/    
 ___/ / /_/ / __/  __/ /|  /  __/ /_/_____/ ___ |/ / / / /_/ / / /_/ / / /_/  __/ /        
/____/\__,_/_/  \___/_/ |_/\___/\__/     /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/            
                                                              /____/       
                            ____  / /_  _______
                           / __ \/ / / / / ___/
                          / /_/ / / /_/ (__  ) 
                         / .___/_/\__,_/____/  
                        /_/                    
'''
#######################################################
#    SafeNet-AnalyzerPlus.py
#
# SafeNet Analyzer Plus is a network traffic analysis
# tool that allows you to capture and analyze packets
# in real time, scan ports, monitor network 
# performance and analyze firewall logs, all from a
# single command line interface.
#
#
# 10/18/23 - Changed to Python3 (finally)
#
# Author: Facundo Fernandez 
#
#
#######################################################

import os
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP
from scapy.all import sniff, Raw
import nmap
import psutil
import pyinotify
import sqlite3

logfile = "logs.txt"
firewall_logfile = "firewall.log"
sent_bytes_limit = 10000000
received_bytes_limit = 10000000

# Inicializar una conexión a la base de datos SQLite
conn = sqlite3.connect('captured_data.db')
cursor = conn.cursor()

# Crear una tabla para almacenar datos de paquetes
cursor.execute('''
    CREATE TABLE IF NOT EXISTS captured_packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        destination_ip TEXT,
        content TEXT
    )
''')
conn.commit()

def analyze_packet(packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport == 80 or packet[TCP].dport == 443:
            # Aquí puedes agregar el código para analizar paquetes en los puertos 80 y 443
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load.decode(errors='ignore')
                if "HTTP" in raw_data:
                    print("Captured an HTTP Packet:")
                    print("Source IP: " + packet[IP].src)
                    print("Destination IP: " + packet[IP].dst)
                    print("HTTP Packet:", raw_data)

                source_ip = packet[IP].src
                destination_ip = packet[IP].dst

                cursor.execute('''
                    INSERT INTO captured_packets (source_ip, destination_ip, content)
                    VALUES (?, ?, ?)
                ''', (source_ip, destination_ip, raw_data))
                conn.commit()

                if packet.haslayer(HTTP):
                    http_packet = packet[HTTP]
                    print("HTTP Packet - Source IP: {}, Destination IP: {}, URL: {}"
                        .format(source_ip, destination_ip, http_packet.Host.decode()))


def check_logs():
    log_number = 1
    while os.path.isfile(f"logs{log_number}.txt"):
        log_number += 1

    logfile = f"logs{log_number}.txt"

    if os.path.isfile("logs.txt"):
        with open("logs.txt", "r") as file:
            for entry in file:
                if "suspicious_activity" in entry:
                    print("Suspected activity found:", entry.strip())
                    with open(logfile, "a") as new_file:
                        new_file.write(entry)

# Definir una función para registrar actividad sospechosa en el archivo de registro principal
def log_suspicious_activity():
    with open("logs.txt", "a") as file:
        file.write("suspicious_activity: Something suspicious happened\n")

def analyze_traffic():
    filter = "tcp port 80"
    sniff(filter=filter, prn=analyze_packet)

def scan_network():
    ip_address = "192.168.1.1-10"
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip_address, arguments="-p 1-1000 -T4")

    for host in scanner.all_hosts():
        print("IP Address:", host)
        for port, state in scanner[host].all_tcp():
            print("Port:", port, "State:", state)

def monitor_performance():
    stats = psutil.net_io_counters()

    if stats.bytes_sent < sent_bytes_limit or stats.bytes_recv < received_bytes_limit:
        print("Network performance is abnormal.")

def analyze_firewall():
    if os.path.isfile(firewall_logfile):
        with open(firewall_logfile, "r") as file:
            for entry in file:
                if "unauthorized_connection" in entry or "suspicious_request" in entry:
                    print("Suspicious activity found in firewall logs:", entry.strip())

def monitor_security_events():
    class EventHandler(pyinotify.ProcessEvent):
        def process_IN_ACCESS(self, event):
            print("File accessed:", event.pathname)

        def process_IN_MODIFY(self, event):
            print("File modified:", event.pathname)

        def process_IN_ATTRIB(self, event):
            print("File attributes changed:", event.pathname)

        def process_IN_CLOSE_WRITE(self, event):
            print("File write closed:", event.pathname)

        # Agregar otros métodos de procesamiento de eventos según sea necesario

    handler = EventHandler()
    wm = pyinotify.WatchManager()
    events = pyinotify.IN_ACCESS | pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB | pyinotify.IN_CLOSE_WRITE
    notifier = pyinotify.Notifier(wm, handler)

    directory = '/var/log'
    wm.add_watch(directory, events)
    notifier.loop()

check_logs()
analyze_traffic()
scan_network()
monitor_performance()
analyze_firewall()
monitor_security_events()
analyze_traffic()

def main():
    print("Checking logs...")
    check_logs()
    print("Analyzing traffic...")
    analyze_traffic()
    print("Scanning network...")
    scan_network()
    print("Monitoring performance...")
    monitor_performance()
    print("Analyzing firewall...")
    analyze_firewall()
    print("Monitoring security events...")
    monitor_security_events()
    print("Analyzing traffic... again")
    analyze_traffic()  # Elimina esta línea para evitar capturar tráfico adicional en el puerto 80

    # Agrega un nuevo filtro para capturar el tráfico en el puerto 443 (HTTPS)
    filter = "port 443"
    sniff(filter=filter, prn=analyze_packet)

if __name__ == "__main__":
    main()
