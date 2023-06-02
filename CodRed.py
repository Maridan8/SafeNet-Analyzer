import os
from scapy.all import sniff, DNS, HTTP, FTP, SMTP
import nmap
import psutil
import pyinotify

logfile = "logs.txt"
firewall_logfile = "firewall.log"
sent_bytes_limit = 10000000
received_bytes_limit = 10000000

def check_logs():
    if os.path.isfile(logfile):
        with open(logfile, "r") as file:
            for entry in file:
                if "suspicious_activity" in entry:
                    print("Suspicious activity found:", entry.strip())

def analyze_traffic():
    def analyze_packet(packet):
        if packet.haslayer(DNS):
            dns_query = packet[DNS]
            if dns_query.qr == 0:  # 0 indicates DNS query / indica consulta DNS
                domain = dns_query.qd.qname.decode()
                if domain == "suspicious_domain.com":
                    print("Suspicious DNS query found:", packet.summary())
            elif dns_query.qr == 1:  # 1 indicates DNS response / indica respuesta DNS
                # You can analyze DNS responses if needed / Puede analizar las respuestas de DNS si es necesario
                pass
        
        if packet.haslayer(HTTP):
            # Analyze HTTP traffic here / Analice el tráfico HTTP aquí
            pass
        
        if packet.haslayer(FTP):
            # Analyze FTP traffic here / Analice el tráfico FTP aquí
            pass
        
        if packet.haslayer(SMTP):
            # Analyze SMTP traffic here / Analice el tráfico SMTP aquí
            pass
    
    filter = "udp port 53 or tcp port 80 or tcp port 21 or tcp port 25"
    sniff(filter=filter, prn=analyze_packet)

def scan_network():
    scanner = nmap.PortScanner()
    ip_address = "192.168.1.0/24"
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

        # Add other event processing methods as needed / Agregue otros métodos de procesamiento de eventos según sea necesario

    # Create an instance of the event handler / Crear una instancia del controlador de eventos
    handler = EventHandler()

    # Create a WatchManager object / Crear un objeto WatchManager
    wm = pyinotify.WatchManager()

    # Add the events you want to monitor / Agregue los eventos que desea monitorear
    events = pyinotify.IN_ACCESS | pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB | pyinotify.IN_CLOSE_WRITE

    # Create a Notifier object with the WatchManager and the event handler / Cree un objeto Notificador con WatchManager y el controlador de eventos
    notifier = pyinotify.Notifier(wm, handler)

    # Add a path to monitor events (e.g., the '/var/log' directory) / Agregue una ruta para monitorear eventos (por ejemplo, el directorio '/var/log')
    directory = '/var/log'
    wm.add_watch(directory, events)

    # Start the main event monitoring loop / Inicie el ciclo de monitoreo de eventos principales
    notifier.loop()

check_logs()
analyze_traffic()
scan_network()
monitor_performance()
analyze_firewall()
monitor_security_events()
