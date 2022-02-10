
import requests
import json

CPE = input("Please enter CPE:\n")
#print(type(CPE))

#query = {"id":"pe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"}
response = requests.get("https://vuln.sentnl.io/api/cvefor/" + CPE)

#cpe:2.3:a:apache:accumulo:1.5.0:*:*:*:*:*:*:*")
#print(type(response))

data = response.json()

print(data)
#print("-" * 40 + "\n")
print(type(data))
#print("-" * 40 + "\n")
#print("DICTIONARY KEYS ARE:")
#print(data.keys())

CVE_list = [data_list['id'] for data_list in data]
CVE = '\n'.join(CVE_list)

CVSS_list = [data_list['cvss'] for data_list in data]

CVSS = '\n'.join(map(str,CVSS_list))

summary_list = [data_list['summary'] for data_list in data]
summary = '\n'.join(summary_list)

link_list = [data_list['references'] for data_list in data]
#print(link_list)
link_list2 = link_list[0]
#print(link_list2)
ext_link = '\n'.join(link_list2)


# get the "misc" key to get a link to remediation

print("CVE: " + CVE + "\n" +
"CVSS: " + str(CVSS) + "\n\n" +
"Summary: " + summary + "\n\n" + 
"External Link(s):\n" + ext_link)


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

