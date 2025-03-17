#!/usr/bin/env python3
import socket
import sys
import threading

def load_ts1_database():
    """
    Reads ts1database.txt where each line is of the form:
    DomainName IPAddress
    """
    db = {}
    with open("ts1database.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line:
                parts = line.split()
                if len(parts) == 2:
                    domain, ip = parts
                    db[domain.lower()] = (domain, ip)
    return db

def log_response(response):
    """Append the given response line to ts1responses.txt."""
    with open("ts1responses.txt", "a") as f:
        f.write(response + "\n")

def handle_client(conn, addr):
    try:
        data = conn.recv(1024).decode().strip()
        if not data:
            conn.close()
            return
        # Expecting: "0 DomainName identification flag"
        parts = data.split()
        if len(parts) != 4:
            conn.close()
            return
        req_type, domain, ident, flag = parts
        domain_lower = domain.lower()
        global ts1_db
        if domain_lower in ts1_db:
            orig_domain, ip = ts1_db[domain_lower]
            response = f"1 {orig_domain} {ip} {ident} aa"
        else:
            response = f"1 {domain} 0.0.0.0 {ident} nx"
        log_response(response)
        conn.sendall(response.encode())
    except Exception as e:
        print("Error in TS1:", e)
    finally:
        conn.close()

def start_ts1_server(rudns_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', int(rudns_port)))
    server_socket.listen(5)
    print("TS1 server listening on port", rudns_port)
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ts1.py rudns_port")
        sys.exit(1)
    rudns_port = sys.argv[1]
    ts1_db = load_ts1_database()
    start_ts1_server(rudns_port)