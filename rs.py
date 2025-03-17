#!/usr/bin/env python3
import socket
import sys
import threading

def load_rs_database():
    """
    Reads rsdatabase.txt.
    The first two lines specify the top-level domains and the corresponding TS hostnames.
    The remaining lines provide mappings for domains not under these TLDs.
    """
    with open("rsdatabase.txt", "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    # First two lines: e.g., "com localhost" and "edu localhost"
    ts1_info = lines[0].split()
    ts2_info = lines[1].split()
    ts1_tld, ts1_hostname = ts1_info[0].lower(), ts1_info[1]
    ts2_tld, ts2_hostname = ts2_info[0].lower(), ts2_info[1]
    # Remaining lines: direct mappings
    local_db = {}
    for line in lines[2:]:
        parts = line.split()
        if len(parts) == 2:
            domain, ip = parts
            local_db[domain.lower()] = (domain, ip)  # preserve original case for domain
    return ts1_tld, ts1_hostname, ts2_tld, ts2_hostname, local_db

def log_response(response):
    """Append the given response line to rsresponses.txt."""
    with open("rsresponses.txt", "a") as f:
        f.write(response + "\n")

def handle_client(conn, addr, rudns_port):
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
        # Determine the TLD by splitting on dot.
        tld = domain_lower.split('.')[-1]
        global ts1_tld, ts1_hostname, ts2_tld, ts2_hostname, rs_local_db

        # Check if the domain is under one of the managed TLDs.
        if tld == ts1_tld or tld == ts2_tld:
            ts_hostname = ts1_hostname if tld == ts1_tld else ts2_hostname
            # For local testing, we define a fixed mapping for TS ports.
            ts_ports = { ts1_tld: 45001, ts2_tld: 45002 }
            if flag == "it":
                # Iterative query: return ns response directing client to TS.
                # The client (for local testing) must use the fixed mapping to know which port to contact.
                response = f"1 {domain} {ts_hostname} {ident} ns"
                log_response(response)
                conn.sendall(response.encode())
            elif flag == "rd":
                # Recursive query: forward the same query to the TS server.
                try:
                    ts_port = ts_ports[tld]
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ts_hostname, ts_port))
                    s.sendall(data.encode())
                    ts_response = s.recv(1024).decode().strip()
                    s.close()
                    # Modify flag: if TS response is authoritative (aa), change to ra.
                    ts_parts = ts_response.split()
                    if len(ts_parts) == 5:
                        resp_type, resp_domain, resp_ip, resp_ident, resp_flag = ts_parts
                        if resp_flag == "aa":
                            resp_flag = "ra"
                        response = f"1 {resp_domain} {resp_ip} {resp_ident} {resp_flag}"
                    else:
                        response = ts_response
                except Exception as e:
                    # On error, reply with non-existent domain.
                    response = f"1 {domain} 0.0.0.0 {ident} nx"
                log_response(response)
                conn.sendall(response.encode())
            else:
                # Unrecognized flag; close connection.
                conn.close()
                return
        else:
            # Domain not under the managed TLDs: RS uses its local database.
            if domain_lower in rs_local_db:
                orig_domain, ip = rs_local_db[domain_lower]
                response = f"1 {orig_domain} {ip} {ident} aa"
            else:
                response = f"1 {domain} 0.0.0.0 {ident} nx"
            log_response(response)
            conn.sendall(response.encode())
    except Exception as e:
        print("Error handling client:", e)
    finally:
        conn.close()

def start_rs_server(rudns_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', int(rudns_port)))
    server_socket.listen(5)
    print("RS server listening on port", rudns_port)
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr, rudns_port)).start()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 rs.py rudns_port")
        sys.exit(1)
    rudns_port = sys.argv[1]
    ts1_tld, ts1_hostname, ts2_tld, ts2_hostname, rs_local_db = load_rs_database()
    start_rs_server(rudns_port)