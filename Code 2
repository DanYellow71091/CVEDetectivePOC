import requests


#cpe:2.3:a:apache:http_server:2.4.12:*:*:*:*:*:*:*
cpe = (input("Please put CPE here:\n"))
#query = {"id":"pe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"}
response = requests.get(f"https://vuln.sentnl.io/api/cvefor/" + cpe)

data = response.json()

#print(data[0])
print("-" * 20)
print(data[0].keys())
print("-" * 20)
print(data[1].keys())
print("-"*20)
