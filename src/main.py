# Python IP Scanner
# Picks random IP addresses and scans them for open HTTP and HTTPS ports.
# Github: https://www.github.com/lewisevans2007/pyipscan
# License: GNU General Public License v3.0
# By: Lewis Evans

import requests
import json
import random
import datetime
from bs4 import BeautifulSoup
import threading
import socket
import sys

with open("ip_list.json", "r") as f:
    ip_list = json.load(f)
    ip_list = ip_list["ip"]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/90.0.818.56 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/90.0.818.56 Safari/537.36 Edg/90.0.818.56",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
]


def get_domain_from_ip(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)
        return domain_name[0]
    except socket.herror as e:
        print(f"Error: {e}")
        return None


def scan_ip(ip):
    try:
        req = requests.get(
            f"http://{ip}",
            headers={"User-Agent": random.choice(user_agents)},
            timeout=2,
        )
    except:
        try:
            req = requests.get(
                f"https://{ip}",
                headers={"User-Agent": random.choice(user_agents)},
                timeout=2,
            )
        except:
            raise Exception("HTTP and HTTPS are not open for ip:" + ip)

    try:
        domain = get_domain_from_ip(ip)
    except:
        domain = "No domain found"
    soup = BeautifulSoup(req.text, "html.parser")
    headers_dict = dict(req.headers)
    try:
        robots_req = requests.get(
            f"http://{ip}/robots.txt",
            headers={"User-Agent": random.choice(user_agents)},
            timeout=2,
        )
    except:
        try:
            robots_req = requests.get(
                f"https://{ip}/robots.txt",
                headers={"User-Agent": random.choice(user_agents)},
                timeout=2,
            )
        except:
            robots_req = None
    if robots_req:
        robots = robots_req.text
    else:
        robots = "No robots.txt found"
    ip_json = {
        "ip": ip,
        "time": datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "headers": headers_dict,
        "status_code": req.status_code,
        "domain": domain,
        "html": req.text,
        "robots.txt": robots,
        "html_title": soup.title.string.strip() if soup.title else "Title not found",
        "html_description": soup.find("meta", {"name": "description"})["content"]
        if soup.find("meta", {"name": "description"})
        else "Description not found",
        "links": [link["href"] for link in soup.find_all("a", href=True)],
        "images": [image["src"] for image in soup.find_all("img", src=True)],
        "scripts": [script["src"] for script in soup.find_all("script", src=True)],
    }
    return ip_json


def scan_and_save_ip():
    while True:
        ip = f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        if ip not in ip_list:
            try:
                ip_json = scan_ip(ip)
                print(f"IT WORKED for {ip}")
                ip_list.append(ip)
                with open(f"data/{ip}.json", "w") as f:
                    json.dump(ip_json, f, indent=4)
                with open("ip_list.json", "w") as f:
                    json.dump({"ip": ip_list}, f, indent=4)
            except Exception as e:
                print(f"Error: {e}")
                ip_list.append(ip)
                with open("ip_list.json", "w") as f:
                    json.dump({"ip": ip_list}, f, indent=4)


try:
    threads = []
    for _ in range(8):
        thread = threading.Thread(target=scan_and_save_ip)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
except KeyboardInterrupt:
    print("KeyboardInterrupt Stopping... If this doesn't work, press Ctrl+C again.")
    sys.exit(0)
