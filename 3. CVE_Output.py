#!/usr/bin/env python3

import requests
import json
import csv
import nmap

#PRINT FORMAT
class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[31m' #RED
    CPE = '\033[0;36m' #CYAN
    RESET = '\033[0m' #RESET COLOR
    UL = '\033[4m' #Under Line
    CPEH = '\u001b[34m'

#CPE = input("Please enter CPE(s):\n")
#print(type(CPE))


#Victoria's Code
#=============================================
#Final output list of string CPEs
inputFinal = []

#Users select from menu
TypeofInput = input ("""\nPlease select from the following:\n 1) To enter CPE value\n 2) To load file with CPE values\n 3) To run an nmap scan \nEnter number:  """)

#1) Manual Input of CPEs
if TypeofInput == "1":
    #String input of CPEs
    CPEsString = input("Enter CPE(s) separated by a comma \",\" :\n")
    #Number of CPEs entered
    if len(CPEsString) > 0:
        NumofCPEs = CPEsString.count(",") + 1
        #One CPE
        if NumofCPEs == 1:
            inputFinal.append(CPEsString)
        #More than one CPE
        elif NumofCPEs > 1:
            if ", " in CPEsString:
                inputFinal = CPEsString.split(", ")
            else:
                print("thisoneworks")
                inputFinal = CPEsString.split(",")
    else:
        print("Input invalid")

    #Test of input#1
#    print(inputFinal)

#file with list of CPEs
if TypeofInput == "2":
    file = input("Enter file name or path:\n") #TODO: need to test if path works

    with open(file) as f:
        lines = f.readlines()
        for item in lines:
            inputFinal.append(item.strip())
#    print(inputFinal)


#NMap Services and Os scan
if TypeofInput == '3':
  scanner = nmap.PortScanner()

  ip_addr = input("Please enter the IP address you would like to scan:\n")
  ports = '1-10000'

  #print(scanner.scan(ip_addr, ports, '-sV'))
  output = scanner.scan(ip_addr, ports, '-sV')
  #print(output['scan']['192.168.56.102']['tcp'])
  inner_dict = output['scan'][ip_addr]['tcp']
  for port_key in inner_dict:
    cpe = inner_dict[port_key]['cpe']
    #print(inner_dict[port_key]['cpe'])
    if cpe not in inputFinal:
      inputFinal.append(cpe.rstrip())


#TODO: Determine input validation; Test input edge cases


#End of Vitoria's Code
#==============================================

'''
# Tony L's code
# ==========================
#!/usr/bin/env python3

import requests
import json

cpe_list = ['cpe:2.3:a:apache:accumulo:1.7.0:*:*:*:*:*:*:*', 'cpe:2.3:a:apache:activemq:5.14.0:*:*:*:*:*:*:*' ]

final_output_dict = {}
final_output_list = []

for cpe in cpe_list:
  cve_output_dict = {}
  response = requests.get("https://vuln.sentnl.io/api/cvefor/" + cpe)


  data = response.json()
  
  CVE_list = [data_list['id'] for data_list in data]
  CVSS_list = [data_list['cvss'] for data_list in data]
  #print (CVE_list, CVSS_list)
  for i in range(len(CVE_list)):
    cve_output_dict['CVE_ID'] = CVE_list[i]
    cve_output_dict['CVSS'] = CVSS_list[i]
    URL = 'https://nvd.nist.gov/vuln/detail/' + CVE_list[i]
    cve_output_dict['URL'] = URL
    dict_copy = cve_output_dict.copy()
    final_output_list.append(dict_copy)
  
  #print(final_output_list)
  final_output_dict[cpe] = final_output_list
  final_output_list = []
print(final_output_dict)
'''

'''
#DANIEL====================================================================================

d = {}
d3 = {}
my_list = []
cpe_range = len(data)
index = 0
CPE = "cpe:2.3:a:apache:http_server:2.4.12:*:*:*:*:*:*:*"

#print(type(counter))
#print(counter)

for i in range(cpe_range):
    d["id"] = data[index]["id"]
    d["cvss"] = int(data[index]["cvss"])
    #d["summary"] = data[index]["summary"]
    #d["references"] = data[index]["references"]
    
    d = d.copy()
    my_list.append(d)
    d.clear()

    #d2["CVE" + "_" + str(index)] = dict(d)

    #d2 = dict(reversed(sorted(d2.items(), key=lambda item: (item[1]["cvss"]))))
    index += 1
  
d3[CPE] = my_list
d3[CPE].pop()
print(d3)
'''

#Tony P.
#============================================================

###validated input
list_CPE = [
  'cpe:/a:apache:activemq_artemis:2.6.3','cpe:2.3:a:apache:http_server:2.4.12:*:*:*:*:*:*:*',
  'cpe:2.3:a:apache:accumulo:1.7.0:*:*:*:*:*:*:*']

###for loop to add each CPE as key to dict_CPE, list_CVE (server response) as value, dict_CVE_attributes ('id', 'CVSS' etc.) as sub-dictionaries
dict_mock_data = {}
# for i in range(len(list_CPE)):
for i in range(len(inputFinal)):
#  response = requests.get("https://vuln.sentnl.io/api/cvefor/" + list_CPE[i])
  response = requests.get("https://vuln.sentnl.io/api/cvefor/" + inputFinal[i])
#  print(type(response))
  data = response.json()
#  print(data)

###mock server response (list of dictionaries by CVE)
#  list_mock_response_per_CPE = [ #list_dict_CVE pfor each CPE
#  {'id':'CVE_1','CVSS':5.1,'summary':'blah','reference':'mah'},
#  {'id':'CVE_2','CVSS':3.2,'summary':'bleh','reference':'meh'},
#  {'id':'CVE_3','CVSS':4.3,'summary':'blih','reference':'mih'}]
#  print(list_CPE[i])
#  print(response_server[i])

#  dict_mock_data[list_CPE[i]] = data #or use mock server response
  dict_mock_data[inputFinal[i]] = data #or use mock server response
#print(dict_mock_data)

###mock CPE:CVE dictionary
#dict_mock_data = {
#  'CPE_1':[
#  {'id':'CVE_1','CVSS':5.1,'summary':'blah','reference':'mah'},
#  {'id':'CVE_2','CVSS':3.2,'summary':'bleh','reference':'meh'},
#  {'id':'CVE_3','CVSS':4.3,'summary':'blih','reference':'mih'}],
#  'CPE_2':[
#  {'id':'CVE_4','CVSS':3.4,'summary':'bloh','reference':'moh'},
#  {'id':'CVE_5','CVSS':5.5,'summary':'bluh','reference':'muh'}]
#  }
#print(dict_mock_data)
#print(len(dict_mock_data))
#print(dict_mock_data.items())

#####list_CVSS = [] #list of CVSS_sorted

###CSV writer_header
header = ["CPE","CVE","CVSS","Summary","References"]
with open('CVE_output.csv', 'w', encoding='UTF8') as f:
  writer = csv.writer(f)
  writer.writerow(header)

###iterate through CPE:CVE_list dictionary ("CPE_input":"server_response_list")
for key_CPE in dict_mock_data:
#  print(dict_mock_data[key_CPE]['message'])
#  print(dict_mock_data[key_CPE].keys())
#  print(dict_mock_data[key_CPE].values())
#  print(dict_mock_data[key_CPE].get('message'))
  if type(dict_mock_data[key_CPE]) == dict and dict_mock_data[key_CPE].get('message') == "No cves found":
#    print("testing")
    dict_noCVE = {'id':'No CVE found','cvss':0.0,'summary':'N/A','references':'N/A'}
    dict_mock_data[key_CPE].update(dict_noCVE)
#    print(dict_mock_data[key_CPE])
    dict_mock_data[key_CPE] = [dict_mock_data[key_CPE]]
#    print(dict_mock_data)
#  else:
#    print(dict_mock_data[key_CPE]['message'])
#  else:
#    dict_mock_data[key_CPE] = dict_mock_data[key_CPE]

#print(dict_mock_data)
#for key_CPE in dict_mock_data:
for key_CPE in dict_mock_data:
  print(bcolors.CPEH+ key_CPE + bcolors.RESET +"\n")

###sort list of dictionaries (key_CPE:value) by CVSS:value
  dict_mock_data_sorted = sorted(dict_mock_data[key_CPE], key=lambda x: x['cvss'], reverse=True)
#  print(dict_mock_data_sorted)

###iterate through list_dict_CVE per CPE
  for dict_CVE in dict_mock_data_sorted:
#    print(dict_CVE)
    print("| " + str(dict_CVE['id']) + " ", end="")
  
    if dict_CVE['cvss'] <= 3.9:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.OK+" [LOW]"+bcolors.RESET + '\n')
  
    elif dict_CVE['cvss'] >= 4.0 and dict_CVE['cvss'] <= 6.9:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.WARNING + " [MEDIUM]"+bcolors.RESET + '\n')
  
    elif dict_CVE['cvss'] >= 7.0:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.FAIL +" [HIGH]"+bcolors.RESET + '\n')
      
      #print("| Summary | " + str(dict_CVE['summary'][:100] + "\n")
  
    print(bcolors.UL+"NIST URL:" + " https://nvd.nist.gov/vuln/detail/" + str(dict_CVE['id'])+bcolors.RESET + '\n')
      
    print("-" * 70 + '\n')
#    print("| References | " + str(dict_CVE['references']) + "\n")
#out_2    print("\n")

###CSV writer_data
    data = [
      key_CPE,str(dict_CVE['id']),
      str(dict_CVE['cvss']),
      str(dict_CVE['summary']),
      str(dict_CVE['references'])
      ]
#    print(data)
    with open('CVE_output.csv', 'a', encoding='UTF8') as f:
      writer = csv.writer(f)
      writer.writerow(data)

#####    list_CVSS.append(dict_CVE['CVSS'])
#####    print(list_CVSS)

#out_2    for key_CVE in dict_CVE: #iterate through dict_CVE ##loop-format
#out_2      print(key_CVE + " = " + str(dict_CVE[key_CVE]))


#Tony P.
#============================================================

'''
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
