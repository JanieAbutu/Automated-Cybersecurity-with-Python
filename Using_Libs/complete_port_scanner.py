####################################################################################################
# Ultimate Port Scanner with Banner Grabbing, Nmap Scan, Shodan Lookup, CSV + HTML Report
#
# Features:                                                                                       #
# - Accepts target host and port range                                                            #
# - Scans ports using socket                                                                       #
# - Banner grabbing from open ports                                                               #
# - Optional Shodan enrichment                                                                    #
# - Nmap scan (-sV) for detailed service info                                                     #                                                                    #
# - Multithreading for faster scanning                                                            #
# - Progress bar with tqdm                                                                        #
# - Detects common services from banner keywords  
# - Optional Nmap scan
# - CSV output with timestamp 
# - HTML report
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


# -----------------------------------------------------------------------------------
# SECTION 1 — Resolve Hostname to IP address
# -----------------------------------------------------------------------------------
def resolve_host(hostname):

    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.error:
        print(f"[!] Could not resolve host: {hostname}")
        return None


# -----------------------------------------------------------------------------------
# SECTION 2 — Socket Port Scanner + Banner Grabbing
# -----------------------------------------------------------------------------------
def scan_port(host, port):
    #Scan a single TCP port

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.settimeout(1)

    banner = ""
    is_open = False

    try:
        result = tcp_socket.connect_ex((host, port))

        # If connection succeeds
        if result == 0:
            is_open = True

            # Try grabbing banner (0.5s timeout)
            try:
                tcp_socket.settimeout(0.5)
                data = tcp_socket.recv(1024)
                banner = data.decode("utf-8", errors="ignore").strip()
            except (socket.timeout, socket.error):
                banner = ""
            except Exception:
                banner = ""
    except (socket.timeout, socket.error):
        is_open = False
    except Exception as e:
        print(f"[!] Error scanning port {port}: {e}")
        is_open = False


    finally:
        tcp_socket.close()

    return is_open, banner


# -----------------------------------------------------------------------------------
# SECTION 3 — Nmap Scan
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
        nm.scan(host, ports, arguments="-sV")

        for h in nm.all_hosts():
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

    except Exception as e:
        print(f"[!] Nmap scan failed: {e}")

    return results


# -----------------------------------------------------------------------------------
# SECTION 4 — Shodan Lookup
# -----------------------------------------------------------------------------------
def shodan_lookup(ip, api_key):

    info = {
        "org": "",
        "os": "",
        "country": "",
        "ports": [],
        "banners": []
    }

    if not shodan:
        print("[!] Shodan library not installed")
        return info

    if not api_key:
        return info

    try:
        api = shodan.Shodan(api_key)
        result = api.host(ip)

        info["org"] = result.get("org", "")
        info["os"] = result.get("os", "")
        info["country"] = result.get("country_name", "")
        info["ports"] = result.get("ports", [])
        for item in result.get('data', []):
            banner = item.get('data', '').strip()
            if banner:
                info['banners'].append(banner)

    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")

    return info


# -----------------------------------------------------------------------------------
# SECTION 5 — Save CSV Report
# -----------------------------------------------------------------------------------
def save_to_csv(results, filename="scan_results.csv"):

    fields = ["timestamp", "host", "ip", "port", "state", "service", "banner", "notes"]

    with open(filename, "w", newline="", encoding="utf-8") as f:

        writer = csv.DictWriter(f, fieldnames=fields)

        writer.writeheader()

        for row in results:
            writer.writerow(row)

    print(f"\n[+] CSV saved: {filename}")


# -----------------------------------------------------------------------------------
# SECTION 6 — Save HTML Report
# -----------------------------------------------------------------------------------
def save_to_html(results, filename="scan_report.html"):

    with open(filename, "w", encoding="utf-8") as f:

        f.write("<html>")
        f.write("<head><title>Port Scan Report</title></head>")
        f.write("<body>")

        f.write("<h2>Port Scan Report</h2>")
        f.write("<table border='1' cellpadding='5'>")

        # Table headers
        f.write("""
        <tr>
        <th>Timestamp</th>
        <th>Host</th>
        <th>IP</th>
        <th>Port</th>
        <th>State</th>
        <th>Service</th>
        <th>Banner</th>
        <th>Notes</th>
        </tr>
        """)

        # Table rows
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

        f.write("</table>")
        f.write("</body></html>")

    print(f"[+] HTML report saved: {filename}")


# -----------------------------------------------------------------------------------
# SECTION 7 — Main Program
# -----------------------------------------------------------------------------------
def main():
    start_time = datetime.now()

    # --- Command line arguments ---
    parser = argparse.ArgumentParser(description="Ultimate Port Scanner")

    parser.add_argument("host", help="Target host to scan")
    parser.add_argument("ports", help="Port range to scan")
    parser.add_argument("--shodan", help="Optional Shodan API key")

    # To allow program to run in both CLI and Jupyter
    if "ipykernel" in sys.modules:
        print("[*] No CLI arguments detected. Entering Notebook mode and using default scan.")
        args = parser.parse_args(["scanme.nmap.org", "1-1000"])
    else:
        args = parser.parse_args()


    host = args.host
    start_port, end_port = map(int, args.ports.split("-"))
    ip = resolve_host(host)

    if not ip:
        return

    results = []

    # --- Shodan lookup ---
    shodan_info = shodan_lookup(ip, args.shodan)


    # --- Multithreaded socket scanning with tqdm progress bar ---
    ports = range(start_port, end_port + 1)
    print(f"\n[+] Scanning {host} ({ip}) ports {start_port}-{end_port}...\n")

    executor = ThreadPoolExecutor(max_workers=250)
    futures = {executor.submit(scan_port, ip, port): port for port in ports}

    iterator = as_completed(futures)

    if tqdm:
        iterator = tqdm(iterator, total=len(futures), desc="Scanning")

    for future in iterator:

        port = futures[future]
        is_open, banner = future.result()

        service_detected = ""
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                service_detected = "SSH"
            elif "http" in banner_lower:
                service_detected = "HTTP"
            elif "smtp" in banner_lower:
                service_detected = "SMTP"
            elif "ftp" in banner_lower:
                service_detected = "FTP"

        if is_open:

            notes = "Socket scan"
            if shodan_info["org"]:
                notes += f" | Org: {shodan_info['org']}"

            row = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "host": host,
                "ip": ip,
                "port": port,
                "state": "open",
                "service": service_detected,
                "banner": banner,
                "notes": notes
            }

            results.append(row)

            #---------------------------------------------
            # Display tqm and open ports with its service
            #---------------------------------------------

            GREEN = "\033[92m"

            msg = f"{GREEN} ==>> OPEN PORT {port}"
            if service_detected:
                msg += f" ({service_detected})"
            if banner:
                msg += f" | Banner: {banner}"
            
            if tqdm:
                tqdm.write(msg)
            else:
                print(msg)



    # --- Ask if user wants Nmap scan ---
    if tqdm:
        print()

    print("Do you want to run Nmap scan as well? (y/n): ")
    use_nmap = input()

    if use_nmap.lower() == "y":

        nmap_results = nmap_scan(host, f"{start_port}-{end_port}")

        for r in nmap_results:

            print(f"{GREEN}[NMAP] Port {r['port']} {r['state']} | {r['service']} {r['version']}")

            row = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "host": host,
                "ip": ip,
                "port": r["port"],
                "state": r["state"],
                "service": r["service"],
                "banner": r["banner"],
                "notes": "Detected by Nmap"
            }

            results.append(row)
            

    # --- Scan summary ---
    total_open = len(results)
    
    # Count ports detected by each scanner
    # Socket ports
    socket_ports = sorted({r["port"] for r in results if "Socket" in r["notes"]})
    # Nmap ports
    nmap_ports   = sorted({r["port"] for r in results if "Nmap" in r["notes"]})


    # Count total unique open ports
    unique_count = len({r["port"] for r in results})

    print("\n---------------------------------")
    print("Scan Summary")
    print("---------------------------------")
    print(f"Target: {host} ({ip})")
    print(f"Ports scanned: {start_port}-{end_port}")
    print(f"Ports found by socket scanning: {len(socket_ports)} -> {socket_ports}")
    print(f"Ports found by Nmap: {len(nmap_ports)} -> {nmap_ports}")
    print(f"Total unique open ports: {unique_count}")
    print("---------------------------------")
    


    # --- Save reports ---
    save_to_csv(results)
    save_to_html(results)

    end_time = datetime.now()
    duration = end_time - start_time

    print(f"Scan duration: {duration}")


# -----------------------------------------------------------------------------------
# Run program
# -----------------------------------------------------------------------------------
if __name__ == "__main__":
    main()