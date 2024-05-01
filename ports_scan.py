import socket
#from urllib.parse import urlparse
#import argparse

def scan(folder_name,domain_name):
#https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
#well knowtn web servers ports : ftp :20,21, ssh 22,telnet 23, smtp 25, dns 53, http 80 , https 443 ,http? test 8081,8080,, mssql 1433, oracle 1521, rdp 3389, postgre 5432, mysql 3306
    file=open(folder_name+"/ports.txt", "a")
    ports = [20,21,22, 23,25,53, 80, 443, 8080, 8081,8443,1433,1521,3389,5432,3306]

    print(f"Enumerating applications on for well known ports: {domain_name}")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain_name, port))
            if result == 0:
                print(f"Port {port} is open")
                file.write(f"Port {port} is open\n")
            else:
                print(f"Port {port} is closed")
                #file.write(f"Port {port} is closed\n")
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
            file.write(f"Error scanning port {port}: {e}\n")
    file.close()
