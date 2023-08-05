# Python IP Scanner
# Picks random IP addresses and scans them for open HTTP and HTTPS ports.
# Github: https://www.github.com/lewisevans2007/pyipscan
# License: GNU General Public License v3.0
# By: Lewis Evans

# Stats shows the statistics of the scan.
# It shows the number of IP addresses scanned, and the total working

import json
import os

with open("ip_list.json", "r") as f:
    ip_list = json.load(f)
    ip_list = ip_list["ip"]

total_ips = len(ip_list)

working_ips = 0

for file in os.listdir("data"):
    working_ips += 1

print(f"Total IP addresses scanned: {total_ips}")
print(f"Working IP addresses scanned: {working_ips}")
print(f"Percentage of IP addresses scanned that work: {round(working_ips / total_ips * 100, 2)}%")
print(f"Percentage of the internet scanned: {round(total_ips / 4294967295 * 100, 10)}%")