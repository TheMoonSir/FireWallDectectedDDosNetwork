"""
Warning ⚠️

Please do not touch the code if you dont know how network work or to coding.

This project doesn't block 100% IP!
You gotta change the block function and unblock function with Router API (Instand netsh filter) for block the ip permanent or timestamp.

Any crime you see that the IP is keep spamming your router (DDOS)
PLEASE CONTENT YOUR ROUTER COMPANY SUPPORT TO BLOCK HIM / BLOCK HIM ON ROUTER ON COMPANY WEBSITE!


Make sure you have anything for use the project!


Steps:
1. Create folder logs :)
2. Go to https://ipapi.is/app/signup and put your API key to "YOUR KEY"


WHAT THIS WILL DO:

Will check if there an IP that spamming your IP 
If yes - will log to firewall.log (Log) that someone tried to spam + timestamp.
If no - won't do something

If IP spamming you more than 5 its will block permanent!
If IP is VPN/Proxy this will be blocked ALSO MAKE SURE YOU AREN'T USING VPN BECAUSE THE API CHECK IF IP IS VPN/PROXY!


"""


import os
import socket
import requests
import subprocess
import time
import scapy.all as scapy
from typing import Literal, Optional

Logs = "logs/"
key = "YOUR KEY" ## https://ipapi.is/app/signup
log_file = os.path.join(Logs, "firewall.log")
blocked_file = os.path.join(Logs, "blocked.log")
Hold = 3000
Windows_Watch = 10
req_times = dict()
req_count = dict()
Stop = {}
Stop_Attempts = 5
cleanup = 300
ListAllow = [""] ## Add your IP!! for won't block anytimes your ip
last_cleanup = time.time()

if not os.path.exists(log_file):
    with open(log_file, 'w') as f:
        print("FireWall Log was not install, now its does.")

if not os.path.exists(log_file):
    with open(blocked_file, 'w') as f:
        print("Blocked Log was not install, now its does.")

## wont block known IPs
AllowKnown = [
    "google", "youtube", "github", "facebook", "instagram", 
    "roblox", "microsoft", "akamai", "aws", "cloudflare", "apple"
]
def is_famous_service(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        hostname = hostname.lower()
        for key in AllowKnown:
            if key in hostname:
                print(f"[Safe] Skipping known service: {key} ({hostname})")
                return True
    except socket.herror:
        pass
    return False

types = Literal["permanent", "timestamp"]
def logging(src, reason, type = types, location: Optional[str] = "Not found", isp: Optional[str] = "Not found"):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    if type == "permanent":
        log_entry = f"[{timestamp}] permanent blocked: {src} | reason: {reason} | location - {location} | isp - {isp}\n"
        target = blocked_file
    else:
        log_entry = f"[{timestamp}] timestamp blocked: {src} | reason: {reason} | location - {location} | isp - {isp}\n"
        target = log_file

    with open(target, "a") as f:
        f.write(log_entry)
    print(f"[{type.upper()}] {log_entry.strip()}")

# https://serverfault.com/questions/851922/blocking-ip-address-with-netsh-filter
def block(src, always=False, reason="", location: Optional[str] = "Not found", isp: Optional[str] = "Not found"):
    if src in Stop:
        return

    blockc = f'netsh advfirewall firewall add rule name="IP Block" dir=in interface=any action=block remoteip={src}'
    try: 
        subprocess.run(blockc, shell=True, check=True)
        if always:
            Stop[src] = -1
            logging(src, reason, "permanent", location, isp)
        else:
            Stop[src] = time.time()
            logging(src, reason, "timestamp", location, isp)
    except subprocess.CalledProcessError as e:
        print(f"Found an error on function 'block' , couldn't block the IP - {e}")

def unblock(src):
    if src in Stop and Stop[src] == -1:
            return

    unblockc = f'netsh advfirewall firewall delete rule name="IP Block" remoteip={src}'
    try: 
        subprocess.run(unblockc, shell=True, check=True)
        del Stop[src]
        if src in req_times: req_times[src] = []
    except subprocess.CalledProcessError as e:
        print(f"Found an error on function 'unblock' , couldn't unblock the IP - {e}")

def clear_stoper():
    global last_cleanup
    now = time.time()
    stop_items = list(Stop.items())
    unlock = []

    for src, ts in stop_items:
        if ts != -1 and (now - ts) > 30:
            unlock.append(src)

    for src in unlock:
        unblock(src)

    if now - last_cleanup > cleanup: 
        print("Cleanup memory")
        remove = []
        for ip, timestamps in list(req_times.items()):
            if not timestamps or (now - timestamps[-1] > cleanup):
                if ip not in Stop or Stop[ip] != -1:
                    remove.append(ip)

        for ip in remove:
            if ip in req_times: del req_times[ip]
            if ip in req_count: del req_count[ip]

        last_cleanup = now
        print("Finish to cleanup memory")
    
def is_blocked(ip):
    return ip in Stop

def load_firewall():
    if os.path.exists(blocked_file):
        with open(blocked_file, "r") as f:
            for line in f:
                if "permanent blocked:" in line:
                    ip = line.split("permanent blocked:")[1].split("|")[0].strip()
                    Stop[ip] = -1 
        print(f"[*] Done. {len(Stop)}")

def ThreadWatch(pocket):
    if scapy.IP in pocket:
        src = pocket[scapy.IP].src
        if src in ListAllow or src in Stop: return

        clear_stoper()

        current_time = time.time()

        if src not in req_times:
            req_times[src] = []

        req_times[src].append(current_time)

        req_times[src] = [x for x in req_times[src] if current_time - x <= Windows_Watch]

        if (len(req_times[src])) > Hold:
            if is_famous_service(src): 
                req_times[src] = [] 
                return
            
            req_count[src] = req_count.get(src, 0) + 1
            
            """

                Exmaple output from the IP.
                

                https://api.ipapi.is?q={src}&key=e8ef2b35ba8aa73538e2
                {
                    "ip": "50.199.140.102",
                    "rir": "ARIN",
                    "is_bogon": false,
                    "is_mobile": false,
                    "is_satellite": false,
                    "is_crawler": false,
                    "is_datacenter": false,
                    "is_tor": false,
                    "is_proxy": false,
                    "is_vpn": false,
                    "is_abuser": false,
                    "company": {
                        "name": "Comcast Cable Communications, LLC",
                        "abuser_score": "0.0007 (Low)",
                        "domain": "comcast.com",
                        "type": "isp",
                        "network": "50.199.128.0 - 50.199.143.255",
                        "whois": "https://api.ipapi.is/?whois=50.199.128.0"
                    },
                    "abuse": {
                        "name": "Comcast Cable Communications, LLC",
                        "address": "1800 Bishops Gate Blvd, Mt Laurel, NJ, 08054, US",
                        "email": "abuse@comcast.net",
                        "phone": "+1-888-565-4329"
                    },
                    "asn": {
                        "asn": 7922,
                        "abuser_score": "0.0001 (Very Low)",
                        "route": "50.128.0.0/9",
                        "descr": "COMCAST-7922, US",
                        "country": "us",
                        "active": true,
                        "org": "Comcast Cable Communications, LLC",
                        "domain": "comcast.com",
                        "abuse": "abuse@comcast.net",
                        "type": "isp",
                        "created": "1997-02-14",
                        "updated": "2021-01-25",
                        "rir": "ARIN",
                        "whois": "https://api.ipapi.is/?whois=AS7922"
                    },
                    "location": {
                        "is_eu_member": false,
                        "calling_code": "1",
                        "currency_code": "USD",
                        "continent": "NA",
                        "country": "United States",
                        "country_code": "US",
                        "state": "Pennsylvania",
                        "city": "Scranton",
                        "latitude": 41.40916,
                        "longitude": -75.6649,
                        "zip": "18502",
                        "timezone": "America/New_York",
                        "local_time": "2025-12-25T17:55:43-05:00",
                        "local_time_unix": 1766703343,
                        "is_dst": false
                    },
                    "elapsed_ms": 0.6
                }
                """
            try:
                information = requests.get(url=f"https://api.ipapi.is?q={src}&key={key}").json()
                if information:
                    is_vpn = information['is_vpn'] if 'is_vpn' in information else False
                    is_proxy = information['is_proxy'] if 'is_proxy' in information else False
                    location = information['location'] if 'location' in information else "Not Found"
                    isp = information['company'] if 'company' in information else "Not Found"

                    print(f"Detected an network attack (?) | Analyzing now information - ({src})")

                    if is_vpn or is_proxy:
                        block(src, always=True, reason="vpn/proxy detected with ddos/dos", location=location, isp=isp)
                    elif req_count[src] >= Stop_Attempts:
                        block(src, always=True, reason="reached attempts ddos/dos", location=location, isp=isp)
                    else:
                        block(src, always=False, reason=f"Trying ddos/dos? | ({src}) is on {req_count[src]} request count.", location=location, isp=isp)
                else:
                    block(src, always=False, reason=f"Trying ddos/dos? | ({src}) is on {req_count[src]} request count.")
            except requests.exceptions.RequestException as e:
                block(src, always=False, reason=f"API is failed, but still blocked (not forever)")

print("FireWall started now.")
load_firewall()
block_list = [ip for ip, val in Stop.items() if val == -1]
bpf_filter = "not host " + " and not host ".join(block_list) if block_list else ""
scapy.sniff(filter=bpf_filter, prn=ThreadWatch, count=0)