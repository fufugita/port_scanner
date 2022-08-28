#!/usr/bin/python3

# Imports necessary librarys
from socket import socket, AF_INET, SOCK_STREAM
import argparse
import threading
import time

# Creates arguments for command line input
def get_arguments():
    parser = argparse.ArgumentParser(description="Python Port Scanner - A python script that scans for open ports on a host")
    parser.add_argument("-t", "--target", action="store", help="This option requires you to provide a target ip address to scan, if none is given it will scan the localhost instead.")
    parser.add_argument("-p", "--ports", action="store", help="This option requires you to provide a single port or port range to scan (1-65535).")
    parser.add_argument("-o", "--options", action="store", help="One of the three options must be selected: 1 - Scans the 10 most common ports, 2 - Scans for only priviliged ports (1-1023), 3 - Scans for any existing web server running on the port 80\HTTP or 443\HTTPS on a host.")
    args = parser.parse_args()

    # Checks if user inputs target IP Address, if none is given scans localhost
    if not args.target:
        print("Scanning localhost...")
        args.target = "127.0.0.1"

    # Checks if user inputs any other arguments, if none are inputed scans all ports
    if not args.ports and not args.options:
        args.ports = "1-65535"

    # Checks if user inputs '-o --option' argument and what option is desired
    if args.options:
        if args.ports:
            print("Scanning given port(s)...")
        if args.options == "1":
            args.ports = [20, 21, 22, 23, 25, 53, 80, 110, 119, 443]
        elif args.options == "2":
            args.ports = "1-1023"
        elif args.options == "3":
            args.ports = [80, 443]
        else:
            print("Invalid option, quitting...")
            quit()
    
    return args

# Class to scan ports
class PortScanner:
    def __init__(self, target, ports, options):

        # Creates global variables for Class
        self.target = target
        self.ports = ports
        self.options = options
        self.banner = None
    
    # Function if a port is open using 'socket'
    def scan_ports(self, port):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(2)

        try:

            # Tries to connect to port
            s.connect((self.target, port))
            port = "{0}".format(port)

            # Tries to get banner, if none is retrieved prints normally as an open port
            try:
                self.banner = s.recv(1024).decode().lower()
                print("Port {0} is open with banner {1}".format(port, self.banner))
            except:
                print("Port {0} is open.\n".format(port))
           
            s.close()
        except:
            pass
        
    # Fuction that runs the scan and check the given ports
    def scan(self):
        print("\nScanning IP: {0}...".format(self.target))

        # Since the port range in some cases is given in string format it transforms in a list with appropriate range
        if (isinstance(args.ports, str)):
            initial_port = int(self.ports.split("-")[0])
            last_port = int(self.ports.split("-")[1])
            self.ports = list(range(initial_port, last_port + 1))

        # Timer starts
        start_time = time.time()
        for port in self.ports:
            # Scans any given ports
            thread = threading.Thread(target=self.scan_ports(port), args=[port])
            thread.start()
        # Timer ends
        end_time = time.time() 

        print("To scan all ports it took {0:.2f} seconds".format(end_time-start_time))

        # Checks inside the banner string what OS the target is running
        if "debian" or "ubuntu" in self.banner:
            print("OS: Linux")
        elif "windows" in self.banner:
        	print("OS: Windows")
            
# Script initialization and calls the 'get_arguments' function and 'PortScanner' class
if __name__ == '__main__':
    args = get_arguments()
    scanner = PortScanner(target=args.target, ports=args.ports, options=args.options)
    scanner.scan()

