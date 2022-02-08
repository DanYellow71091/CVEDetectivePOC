#!/usr/bin/env python3

import requests

query = {"id":"pe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"}
response = requests.get("https://vuln.sentnl.io/api/cve/CVE-2016-3333",params = query)
data = response.json()

print(data)
print("-" * 40 + "\n")
print(type(data))
print("-" * 40 + "\n")
print("DICTIONARY KEYS ARE:")
print(data.keys())
