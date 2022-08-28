# Port Scanner

Python Port Scanner script using mainly the socket library.


## Usage:

- To scan a target, the user must provide an IPv4 Address using the -t argument;
- If no IPv4 Address is given, it will use localhost (127.0.0.1);
- A port range can be provided using the -p argument (e.g.: 53-443);
- If no range is provided, then the script will scan all 65535 ports;
- Using the -o argument, the user can choose from 3 different options:
  - Option 1 will scan the 10 most common ports that are usually open (20, 21, 22, 23, 25, 53, 80, 110, 119, 443);
  - Option 2 will scan only private ports (1-1023);
  - Option 3 will scan only HTTP and HTTPS ports (80 and 443);
- The user must use python3 to run the script.
Examples:
```
python3 port_scanner.py -t 8.8.8.8
```
- This will scan all 65535 ports.

```
python3 port_scanner.py -t 8.8.8.8 -p 53-553
```
- This will scan from port 53 to port 443.

```
pytho3 port_scanner.py -t 8.8.8.8 -o 1
```
- This will scan the 10 most common ports to be open (20, 21, 22, 23, 25, 53, 80, 110, 119, 443).

