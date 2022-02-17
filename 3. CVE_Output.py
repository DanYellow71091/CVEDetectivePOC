#!/usr/bin/env python3

import requests
import json
import csv
import nmap

#PRINT FORMAT
class bcolors:
    MEDIUM = '\033[92m' #GREEN
    HIGH = '\033[93m' #YELLOW
    CRITICAL = '\033[31m' #RED
    LOW = '\033[1;37m' # WHITE
    CPE = '\033[0;36m' #CYAN
    RESET = '\033[0m' #RESET COLOR
    UL = '\033[4m' #Under Line
    CPEH = '\u001b[34m'

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
                #print("thisoneworks")
                inputFinal = CPEsString.split(",")
    else:
        print("Invalid input.")

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
      inputFinal.append(cpe)


#TODO: Determine input validation; Test input edge cases


dict_CPE = {}
dict_noCVE = {'id':'No CVEs found','cvss':'N/A','summary':'N/A','references':'N/A'}
dict_error = {'id':'No CVEs found, error','cvss':'N/A','summary':'N/A','references':'N/A'}

###for loop to add each CPE as key to dict_CPE, list_CVE (server response) as value, dict_CVE_attributes ('id', 'CVSS' etc.) as sub-dictionaries
for i in range(len(inputFinal)):
  response = requests.get("https://vuln.sentnl.io/api/cvefor/" + inputFinal[i])
#  print(response.status_code)
  if response.status_code == 200 or response.status_code == 404:
    data = response.json()
#  print(data)
    dict_CPE[inputFinal[i]] = data
#  print(dict_CPE)
  else:
#    print(bcolors.FAIL + inputFinal[i] + bcolors.RESET + ": error, please check CPE")
#update dict_CPE with unresponsive CPE queries
    dict_CPE[inputFinal[i]] = [dict_error]
    continue

###iterate through CPE:CVE_list dictionary ("CPE_input":"server_response_list")
for key_CPE in dict_CPE:
#check for CPE w/o CVE
  if type(dict_CPE[key_CPE]) == dict and dict_CPE[key_CPE].get('message') == "No cves found":
#    print(dict_CPE[key_CPE])
#update server response (dictionary) to list_dict_noCVE
    dict_CPE[key_CPE].update(dict_noCVE)
    dict_CPE[key_CPE] = [dict_CPE[key_CPE]]
#    print(dict_CPE)

###CSV writer_header
header = ["CPE","CVE","CVSS","Summary"]#,"References"]
with open('CVE_output.csv', 'w', encoding='UTF8') as f:
  writer = csv.writer(f)
  writer.writerow(header)

###iterate through CPE:CVE_list dictionary ("CPE_input":"server_response_list")
for key_CPE in dict_CPE:
  print("-" * 70 + '\n')
  print(bcolors.CPEH + key_CPE + bcolors.RESET + "\n")

###sort list of dict_CVE by CVSS:value, id:value per CPE
  dict_CPE_sorted = sorted(dict_CPE[key_CPE], key=lambda x: (x['cvss'], x['id']), reverse=True)
#  print(dict_CPE_sorted)

###iterate through list_dict_CVE per CPE to print
  for dict_CVE in dict_CPE_sorted:
#    print(dict_CVE)
    print("| " + str(dict_CVE['id']) + " ", end="")
  
    if type(dict_CVE['cvss']) == str:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.FAIL+" [?]"+bcolors.RESET + '\n')
      continue

    if dict_CVE['cvss'] <= 3.9:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.LOW+" [LOW]"+bcolors.RESET + '\n')
  
    elif dict_CVE['cvss'] >= 4.0 and dict_CVE['cvss'] <= 6.9:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.MEDIUM + " [MEDIUM]"+bcolors.RESET + '\n')
  
    elif dict_CVE['cvss'] >= 7.0 and dict_CVE['cvss' <= 8.9:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.HIGH +" [HIGH]"+bcolors.RESET + '\n')
    
    elif dict_CVE['cvss'] >= 9.0:
      print("| CVSS: " + str(dict_CVE['cvss']) + bcolors.CRITICAL + "[CRITICAL]"
      
#      print("| Summary | " + str(dict_CVE['summary'][:100] + "\n")
  
    print(bcolors.UL+"NIST URL: " + "https://nvd.nist.gov/vuln/detail/" + str(dict_CVE['id'])+bcolors.RESET + '\n')

###CSV writer_data
    data = [
      key_CPE,
      str(dict_CVE['id']),
      str(dict_CVE['cvss']),
      str(dict_CVE['summary']),
#      str(dict_CVE['references'])
      ]
#    print(data)
    with open('CVE_output.csv', 'a', encoding='UTF8') as f:
      writer = csv.writer(f)
      writer.writerow(data)

print("-" * 70)
