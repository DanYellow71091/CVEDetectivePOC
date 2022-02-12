
import requests
import json

CPE = input("Please enter CPE:\n")
#print(type(CPE))

#query = {"id":"pe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"}
response = requests.get("https://vuln.sentnl.io/api/cvefor/" + CPE)

#cpe:2.3:a:apache:accumulo:1.5.0:*:*:*:*:*:*:*")
#print(type(response))

data = response.json()



#Tony P
#substitute dict_mock_data with filtered/desired server response (Daniel O)
#for loop to add each CPE as key to dict_CPE, list_CVE (server response) as value, dict_CVE_attributes ('id', 'CVSS' etc.) as sub-dictionaries

dict_mock_data = {
  'CPE_1':[
  {'id':'CVE_1','CVSS':5.1,'summary':'blah','reference':'mah'},
  {'id':'CVE_2','CVSS':3.2,'summary':'bleh','reference':'meh'},
  {'id':'CVE_3','CVSS':4.3,'summary':'blih','reference':'mih'}],
  'CPE_2':[
  {'id':'CVE_4','CVSS':3.4,'summary':'bloh','reference':'moh'},
  {'id':'CVE_5','CVSS':5.5,'summary':'bluh','reference':'muh'}]
  }
#print(dict_mock_data)
#print(len(dict_mock_data))
#print(dict_mock_data.items())

#list_CVSS = [] #list of CVSS_sorted
for key_CPE in dict_mock_data: #iterate through dict_CPE
  print(key_CPE)

  dict_mock_data_sorted = sorted(dict_mock_data[key_CPE], key=lambda x: x['CVSS'], reverse=True) #sort list of dictionaries (key_CPE:value) by CVSS:value
#  print(dict_mock_data_sorted)

  for dict_CVE in dict_mock_data_sorted: #iterate through list_dict_CVE per CPE
#    print(dict_CVE)
###    print("\t"*2 + "CVE = " + str(dict_CVE['id']), end="") ###hard-format
###    print("\t"*2 + "CVSS = " + str(dict_CVE['CVSS']) + "\n")
###    print("\t"*3 + "Summary = " + str(dict_CVE['summary']) + "\n")
###    print("\t"*3 + "Reference = " + str(dict_CVE['reference']) + "\n")
    print("\n")

#####    list_CVSS.append(dict_CVE['CVSS'])
#####    print(list_CVSS)

    for key_CVE in dict_CVE: #iterate through dict_CVE ##loop-format
      print(key_CVE + " = " + str(dict_CVE[key_CVE]))

  print("-"*66)
  
  
  
'''
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
'''
