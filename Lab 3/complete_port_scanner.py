
####################################################################################################
# Complete Port Scanner with Banner Grabbing, Nmap Scan, Shodan Lookup, CSV + HTML Report
# -----------------------------------------------------------------------------------
# This tool performs layered network reconnaissance against a target host.
# -----------------------------------------------------------------------------------
# Features:                                                                                       #
# - Accepts target host and port range                                                            #
# - Scans ports using socket                                                                      #
# - Banner grabbing from open ports                                                               #
# - Shodan enrichment (optional)                                                                  #
# - Nmap scan (-sV) for detailed service info       (optional)                                    #                                                                    #
# - Multithreading for faster scanning                                                            #
# - Progress bar with tqdm                                                                        #
# - Detects common services from banner keywords  
# - Optional Nmap scan
# - CSV output with timestamp 
# - HTML report
####################################################################################################
####################################################################################################


# %%
####################################################################################################
# # Import libraries required
####################################################################################################

import socket
from datetime import datetime
import csv
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# Optional libraries
try:
    import shodan
except ImportError:
    shodan = None

try:
    import nmap
except ImportError:
    nmap = None

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None



# %%
# -----------------------------------------------------------------------------------
# SECTION 1 — Resolve Hostname to IP address
# -----------------------------------------------------------------------------------
# This ensures the scanner communicates directly with the target host
# using its IP address instead of repeatedly performing DNS lookups.
# -----------------------------------------------------------------------------------


def resolve_host(hostname):
    try:
        return socket.gethostbyname(hostname)               # This performs DNS lookup and returns the IPv4 address
    except socket.error:
        print(f"[!] Could not resolve host: {hostname}")
        return None


# %%
# -----------------------------------------------------------------------------------
# SECTION 2 — Socket Scanner + Banner Grabbing
# -----------------------------------------------------------------------------------

# This function works by attempting to establish a full TCP connection to the target port
# If the connection succeeds, the port is considered open.

# After connecting, the scanner attempts to read any banner data sent by the service, 
# which may reveal application information
# -----------------------------------------------------------------------------------

def scan_port(host, port):
    #Scan a single TCP port

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Create a TCP socket using IPv4 (AF_INET) and TCP protocol (SOCK_STREAM)  
    tcp_socket.settimeout(1)                                          # Set a timeout to avoid long delays on filtered or unresponsive ports

    banner = ""
    is_open = False

    try:
        result = tcp_socket.connect_ex((host, port))

        # If connection succeeds
        if result == 0:                                                     # 0 means connection successful (port open)
            is_open = True


            try:                                                            # Try grabbing banner after a TCP connection is established
                tcp_socket.settimeout(0.5)
                data = tcp_socket.recv(1024)                                # Read up to 1024 bytes from the service
                banner = data.decode("utf-8", errors="ignore").strip()      # Decode banner safely (ignore non-UTF8 bytes)
            except (socket.timeout, socket.error):
                banner = ""
            except Exception:
                banner = ""
    except (socket.timeout, socket.error):
        is_open = False
    except Exception as e:
        print(f"[!] Error scanning port {port}: {e}")
        is_open = False

    # Always close the socket to release system resources
    finally:
        tcp_socket.close()

    return is_open, banner


# %%
# -----------------------------------------------------------------------------------
# Nmap Scan
# -----------------------------------------------------------------------------------

# The -sV option performs version detection by sending specialized probes
# to identify the exact service and application version running on a port.
#
# This provides far richer intelligence than banner grabbing alone.
# -----------------------------------------------------------------------------------


def nmap_scan(host, ports):
    #Run Nmap scan(-sV) for detailed service detection

    results = []

    if not nmap:
        print("[!] python-nmap not installed")
        return results

    try:
        print("\n[+] Running Nmap service detection scan (-sV)...")

        nm = nmap.PortScanner()
        nm.scan(host, ports, arguments="-sV")                                # Execute the Nmap scan

        for h in nm.all_hosts():                                             # Parse results returned by Nmap
            for proto in nm[h].all_protocols():
                for port in nm[h][proto]:

                    info = nm[h][proto][port]

                    results.append({
                        "port": port,
                        "state": info["state"],
                        "service": info["name"],
                        "version": info.get('version', ''),
                        "banner": info.get("product", "")
                    })

        print("[+] Nmap scan completed.\n")

    except Exception as e:                                                  # Handle errors
        print(f"[!] Nmap scan failed: {e}")

    return results


# %%
# -----------------------------------------------------------------------------------
# Shodan Lookup
# -----------------------------------------------------------------------------------

# Function to query shodan throuh its API
# Querying Shodan allows the scanner to enrich results with OSINT data
# such as organization, operating system, country, and previously
# discovered service banners.
# -----------------------------------------------------------------------------------


def shodan_lookup(ip, api_key):

    info = {"org":"", "os":"", "country":"", "ports":[], "banners":[]}

    if not shodan or not api_key:
        return info

    try:

        api = shodan.Shodan(api_key)
        result = api.host(ip)

        info["org"] = result.get("org","")
        info["os"] = result.get("os","")
        info["country"] = result.get("country_name","")
        info["ports"] = result.get("ports",[])

    except Exception as e:
        print(f"[!] Shodan error: {e}")

    return info


# %%
# -----------------------------------------------------------------------------------
# CSV
# -----------------------------------------------------------------------------------
# Function to save results to CSV
# -----------------------------------------------------------------------------------


def save_to_csv(results, filename="scan_results.csv"):

    fields = ["timestamp","host","ip","port","state","service","banner","notes"]

    with open(filename,"w",newline="",encoding="utf-8") as f:

        writer = csv.DictWriter(f,fieldnames=fields)
        writer.writeheader()

        for r in results:
            writer.writerow(r)

    print(f"[+] CSV saved: {filename}")


# %%
# -----------------------------------------------------------------------------------
# HTML
# -----------------------------------------------------------------------------------
# HTML output provides a human-readable report that can be viewed
# directly in a web browser.
# -----------------------------------------------------------------------------------


def save_to_html(results, filename="scan_report.html"):

    with open(filename,"w",encoding="utf-8") as f:

        f.write("<html><body>")
        f.write("<h2>Port Scan Report</h2>")
        f.write("<table border=1>")

        f.write("<tr><th>Time</th><th>Host</th><th>IP</th><th>Port</th><th>State</th><th>Service</th><th>Banner</th><th>Notes</th></tr>")

        for r in results:

            f.write("<tr>")
            f.write(f"<td>{r['timestamp']}</td>")
            f.write(f"<td>{r['host']}</td>")
            f.write(f"<td>{r['ip']}</td>")
            f.write(f"<td>{r['port']}</td>")
            f.write(f"<td>{r['state']}</td>")
            f.write(f"<td>{r['service']}</td>")
            f.write(f"<td>{r['banner']}</td>")
            f.write(f"<td>{r['notes']}</td>")
            f.write("</tr>")

        f.write("</table></body></html>")

    print(f"[+] HTML report saved: {filename}")


# %%
# -----------------------------------------------------------------------------------
# SECTION 7 — Main Program
# -----------------------------------------------------------------------------------
# This function coordinates the entire scanning workflow.
# -----------------------------------------------------------------------------------


def main(argv=None):
    start_time = datetime.now()              # Record scan start time so total scan duration can be calculated

    parser = argparse.ArgumentParser(description="Professional Port Scanner")
    parser.add_argument("host")
    parser.add_argument("ports")
    parser.add_argument("--mode", choices=["socket","nmap","shodan","full"], default="socket", help="Scan mode")
    parser.add_argument("--shodan", help="Shodan API key")
    parser.add_argument("--nmap", action="store_true", help="Run Nmap service detection")

    args = parser.parse_args(argv)

    # Extract target host and parse the port range

    host = args.host
    start_port, end_port = map(int, args.ports.split("-"))
    ip = resolve_host(host)                                 # Resolve hostname to IP address
    if not ip:
        return

    results = []                                            # This list will store all discovered scan results

    GREEN = "\033[92m"

    
    # ---------------------- Shodan ----------------------
    #-----------------------------------------------------

    shodan_info = {"org": "", "os": "", "country": "", "ports": [], "banners": []}
    if args.mode in ["shodan","full"] and args.shodan:
        print("[+] Running Shodan lookup...")
        shodan_info = shodan_lookup(ip, args.shodan)
        print("\n[+] Shodan Intelligence")
        print("---------------------------------")
        print(f"Organization: {shodan_info['org']}")
        print(f"OS: {shodan_info['os']}")
        print(f"Country: {shodan_info['country']}")
        print(f"Known Open Ports: {shodan_info['ports']}")
        print("---------------------------------\n")
        results.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "ip": ip,
            "port": "",
            "state": "info",
            "service": "Shodan",
            "banner": f"OS: {shodan_info['os']} | Known ports: {shodan_info['ports']}",
            "notes": f"Org: {shodan_info['org']} | Country: {shodan_info['country']}"
        })

    # ---------------------- Socket Scan -------------------------
    # --- Multithreaded socket scanning with tqdm progress bar ---
    #-------------------------------------------------------------

    if args.mode in ["socket","full","nmap"]:
        ports = range(start_port, end_port + 1)
        print(f"\n[+] Scanning {host} ({ip}) ports {start_port}-{end_port}...\n")

        executor = ThreadPoolExecutor(max_workers=250)                              # ThreadPoolExecutor manages a pool of worker threads
        futures = {executor.submit(scan_port, ip, port): port for port in ports}    # Submit a scan task for every port in the range
        
        iterator = as_completed(futures)                                            # Yields scan results as soon as each thread finishes
        if tqdm:
            iterator = tqdm(iterator, total=len(futures), desc="Scanning")


        #-------- Process scan results as each thread completes ---------
        for future in iterator:

            port = futures[future]
            is_open, banner = future.result()                                       # Retrieve result from the completed scanning thread


            # Basic Service Identification

            service_detected = ""
            if banner:
                b = banner.lower()
                if "ssh" in b: service_detected="SSH"
                elif "http" in b: service_detected="HTTP"
                elif "smtp" in b: service_detected="SMTP"
                elif "ftp" in b: service_detected="FTP"

            #------- If the port is open, record the scan result -----------

            if is_open:
                notes = "Socket scan"                                               # Add metadata about the scan source
                if shodan_info["org"]:                                              # Include Shodan organization information if available
                    notes += f" | Org: {shodan_info['org']}"


            # Store result in structured dictionary format

                row = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "host": host, "ip": ip, "port": port,
                    "state": "open", "service": service_detected,
                    "banner": banner, "notes": notes
                }

                results.append(row)

            #------------------------------------------------------------
            # Display open ports discovery with its service in real time
            #------------------------------------------------------------
                msg = f"{GREEN} ==>> OPEN PORT {port}"
                if service_detected: 
                    msg += f" ({service_detected})"
                if banner: 
                    msg += f" | Banner: {banner}"
                if tqdm: 
                    tqdm.write(msg)
                else: print(msg)

    # ---------------------- Nmap Scan --------------------------
    #------------------------------------------------------------

    if args.mode in ["nmap","full"] and args.nmap:
        nmap_results = nmap_scan(host, f"{start_port}-{end_port}")

        # Add Nmap results to the overall scan dataset

        for r in nmap_results:
            print(f"{GREEN}[NMAP] Port {r['port']} {r['state']} | {r['service']} {r['version']}")
            row = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "host": host, "ip": ip, "port": r["port"],
                "state": r["state"], "service": r["service"],
                "banner": r["banner"], "notes": "Detected by Nmap"
            }
            results.append(row)

    # ---------------------- Scan Summary ----------------------
    # The summary distinguishes between:
    # - ports discovered via socket scanning
    # - ports discovered via Nmap
    # - total unique open ports
    #------------------------------------------------------------
    
    socket_ports = sorted({r["port"] for r in results if "Socket" in r["notes"]})       # Socket ports
    nmap_ports   = sorted({r["port"] for r in results if "Nmap" in r["notes"]})         # Nmap ports
    unique_count = len({r["port"] for r in results if isinstance(r["port"], int)})      # Count total unique open ports

    print("\n---------------------------------")
    print("Scan Summary")
    print("---------------------------------")
    print(f"Target: {host} ({ip})")
    print(f"Ports scanned: {start_port}-{end_port}")
    print(f"Ports found by socket scanning: {len(socket_ports)} -> {socket_ports}")
    print(f"Ports found by Nmap: {len(nmap_ports)} -> {nmap_ports}")
    print(f"Total unique open ports: {unique_count}")
    print("---------------------------------")

    # ------------- Export results -----------------

    save_to_csv(results)
    save_to_html(results)

    print(f"Scan duration: {datetime.now() - start_time}")                              # Calculate total scan duration


# ---------------------- CLI Entry ----------------------
if __name__ == "__main__" and "ipykernel" not in sys.modules:
    main()



# %%
# -----------------------------------------------------------------------------------
# JUPYTER TESTS
# -----------------------------------------------------------------------------------

# ---------------------- Jupyter Test Cases ----------------------
if "ipykernel" in sys.modules:
    print("\n------------------------------------------------------------\nSOCKET SCAN ONLY\n------------------------------------------------------------")
    main(["scanme.nmap.org","1-1000","--mode","socket"])

    print("\n------------------------------------------------------------\nSOCKET + NMAP\n------------------------------------------------------------")
    main(["scanme.nmap.org","1-1000","--mode","nmap","--nmap"])

    print("\n------------------------------------------------------------\nSOCKET + SHODAN\n------------------------------------------------------------")
    main(["scanme.nmap.org","1-1000","--mode","shodan","--shodan","mW3Zajxc1LHrdG7UBYcUK7F5PpMbSPTG"])

    print("\n------------------------------------------------------------\nFULL SCAN\nn------------------------------------------------------------")
    main(["scanme.nmap.org","1-1000","--mode","full","--nmap","--shodan","YmW3Zajxc1LHrdG7UBYcUK7F5PpMbSPTG"])


