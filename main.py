import socket

# Classe para escanear portas
class PortScanner:
    def __init__(self, ip):
        self.ip = ip
        self.open_ports = []

    # Escâner de portas
    def scan_ports(self, forport):
        print(f'scanning {forport} ....')
        # if port is open update the list
        if self.is_open(forport):
            self.open_ports.append(forport)

    # Função que verifica se a porta está aberta com o 'socket'
    def is_open(self, port):
        s = socket.socket()
        exit_code = s.connect_ex((self.ip, port))
        s.close()
        if exit_code == 0:
            return True
        else:
            return False

    # Escreve portas abertas em um arquivo separado
    def write_to_file(self, path_to_file):
        with open(path_to_file, "w") as f:
            for port in self.open_ports:
                print(port)
                f.write(str(port) + "\n")


def main():
    ip = input("Escreva o endereço IP para escanear: ")
    scanner = PortScanner(ip)
    for x in range(1, 9999):
        scanner.scan_ports(x)
    #print(scanner.open_ports)
    scanner.write_to_file("open_ports.txt")

if __name__ == '__main__':
    main()
