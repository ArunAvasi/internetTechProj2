#!/usr/bin/env python3
import sys
import socket

def main():


    if len(sys.argv) != 2:
        print("Usage: python3 ts2.py <rudns_port>")
        sys.exit(1)

    try:
        rudns_port = int(sys.argv[1])
    except ValueError:
        print("Error: rudns_port must be an integer.")
        sys.exit(1)

    database = {}
    try:
        with open("ts2database.txt", "r") as db_file:
            for line in db_file:
                line = line.strip()
                if not line:
                    continue  # skip empty lines
                domain, ip_addr = line.split()
                database[domain.lower()] = (domain, ip_addr)
    except FileNotFoundError:
        print("Error: ts2database.txt not found in current directory.")
        sys.exit(1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', rudns_port))
    server_socket.listen(5)

    print(f"[TS2] Listening on port {rudns_port} ...")

    with open("ts2responses.txt", "w") as log_file:
        while True:
            client_socket, client_address = server_socket.accept()
            try:
                request_data = client_socket.recv(1024).decode('utf-8').strip()
                if not request_data:
                    client_socket.close()
                    continue

                parts = request_data.split()
                if len(parts) != 4:
                    client_socket.close()
                    continue

                msg_type, domain_name, identification, flags = parts

                if msg_type != "0":
                    client_socket.close()
                    continue

                lookup_key = domain_name.lower()
                if lookup_key in database:
                    stored_domain, ip_address = database[lookup_key]
                    response_flag = "aa"
                    response = f"1 {stored_domain} {ip_address} {identification} {response_flag}"
                else:
                    response_flag = "nx"
                    response = f"1 {domain_name} 0.0.0.0 {identification} {response_flag}"

                client_socket.sendall(response.encode('utf-8'))

                log_file.write(response + "\n")
                log_file.flush()

            finally:
                client_socket.close()

if __name__ == "__main__":
    main()