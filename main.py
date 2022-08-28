#!/usr/bin/python3

from socket import socket, AF_INET, SOCK_STREAM
import scapy.all as scapy
import argparse
import threading
import time

def get_arguments():
    parser = argparse.ArgumentParser(description="Python Port Scanner - A python script that scans for open ports on a host")
    parser.add_argument("-t", "--target", action="store", help="This option requires you to provide a target ip address to scan.")
    parser.add_argument("-p", "--ports", action="store", help="This option requires you to provide a single port or port range to scan (1-65535).")
    parser.add_argument("-l", "--localhost", action="store", help="This option scans the localhost.")
    parser.add_argument("-w", "--web", action="store", help="This option scans for any existing web server running on the port 80\HTTP or 443\HTTPS on a host.")
    parser.add_argument("-o", "--options", action="store", help="One of the three options must be selected: 1 - Scans the 10 most common ports, 2 - Scans for only priviliged ports (1-1023), 3 -.")
    args = parser.parse_args()

    if not args.target:
        print("Please provide a target ip address, scanning localhost instead...")
        quit()

    if not args.ports and not args.localhost and not args.options and not args.web:
        args.ports = "1-65535"

    if args.ports:
        print("Scanning give port(s)...")
    
    if args.localhost:
        print("Scanning localhost...")
        args.target = '127.0.0.1'

    if args.web:
        print("Scanning ports 80 and 443...")
        args.ports = [80, 443]
    
    if args.options:
        if args.ports:
            print("Scanning given port(s)...")
        if args.mode == "1":
            args.ports = [20, 21, 22, 23, 25, 53, 80, 110, 119, 443]
        elif args.mode == "2":
            args.ports = "1-1023"
        elif args.mode == "3":
            print("idk") 
        else:
            print("Invalid option, quitting...")
            quit()
    
    return args

# Classe para escanear portas
class PortScanner:
    def __init__(self, target, ports, options):

        self.target = target
        self.ports = ports
        self.target = options
    
    # Função que verifica se a porta está aberta com o 'socket'
    def scan_ports(self, port):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(2)

        try:

            s.connect((self.target, port))
            port = "{0}".format(port)
            try:
                banner = s.recv(1024).decode()
                print("Port {0} is open with banner {1}.".format(port, banner))
            except:
                print("Port {0} is open.".format(port))
           
            s.close()

        except:
            pass

    def scan(self):
        print("\nScanning IP: {0}...".format(self.target))

        if (isinstance(args.ports, str)):
            initial_port = int(self.ports.split("-")[0])
            last_port = int(self.ports.split("-")[1])
            self.ports = list(range(initial_port, last_port + 1))

        start_time = time.time()
        for port in self.ports:
            self.scan_ports(port)
            thread = threading.Thread(target=self.scan_ports(port), args=[port])
            thread.start()
        end_time = time.time()
        print("To scan all ports it took {0:.2f} seconds".format(end_time-start_time))
            
def main():
    args = get_arguments()
    scanner = PortScanner(target=args.target, ports=args.ports, options=args.options)
    scanner.scan()

if __name__ == '__main__':
    main()
