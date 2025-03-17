#!/usr/bin/env python3
import socket
import sys

def log_response(response):
    """Append the received DNS response to resolved.txt."""
    with open("resolved.txt", "a") as f:
        f.write(response + "\n")

def send_query(hostname, port, query):
    """Create a connection, send the query, and return the response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, int(port)))
    s.sendall(query.encode())
    response = s.recv(1024).decode().strip()
    s.close()
    return response

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 client.py rs_hostname rudns_port")
        sys.exit(1)
    rs_hostname = sys.argv[1]
    rudns_port = sys.argv[2]

    # Clear (or create) resolved.txt at the start.
    open("resolved.txt", "w").close()

    # Fixed mapping for local testing: mapping TLD to TS port.
    ts_ports = {
        "com": 45001,
        "edu": 45002
    }

    # Read the queries from hostnames.txt
    with open("hostnames.txt", "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    query_id = 1
    for line in lines:
        parts = line.split()
        if len(parts) != 2:
            continue
        domain, flag = parts
        # Build the initial query: "0 DomainName identification flag"
        query = f"0 {domain} {query_id} {flag}"
        # Send query to the root server.
        response = send_query(rs_hostname, rudns_port, query)
        log_response(response)
        # For iterative queries, RS replies with an NS response.
        resp_parts = response.split()
        if len(resp_parts) == 5:
            resp_type, resp_domain, resp_ip, resp_ident, resp_flag = resp_parts
            if flag == "it" and resp_flag == "ns":
                # Determine the TS port using fixed mapping based on TLD.
                tld = domain.lower().split('.')[-1]
                ts_port = ts_ports.get(tld, rudns_port)  # fallback if missing
                query_id += 1
                # Build and send a new query directly to the TS server.
                new_query = f"0 {domain} {query_id} {flag}"
                response = send_query(resp_ip, ts_port, new_query)
                log_response(response)
        query_id += 1