# CVE Detective #
![Image](https://security.virginia.edu/sites/security.virginia.edu/files/e%20a%20hack%20detective..jpg)
## Overview  ##
This python script will help to automate finding all (if any) Common Vulnerablility and Exposures (CVEs) associated to any Common Platform Enumeration (CPEs) of a software, applicationm, or OS.  You may input a single CPE, a list of CPEs separated by commas, or a text file of CPEs.  This program also has the functionality to use an NMap scan to find any CPEs of a target machine and output the CVEs associated with all CPEs found on the target machine.

## Features
  * Utilizes vuln.sentnl.io's REST API to get the input of CPEs and output CVE information
    * Output includes the CVE, CVSS, and external link to the NIST's National Vulnerability Database (NVD) to provide a more thorough summary and suggestions for mitigation.
    * For each CPE, their CVE output on the terminal is sorted based on their CVSS scores from highest criticality/priority to the lowest.
    * The program also saves the output into a CSV file in the same folder the script is run in.
  * Includes 3 ways for receving CVE information of CPEs:
    * You may upload a single CPE, or multiple CPEs separated by commas
    * You may upload a text file containing a single, or multiple CPEs.
    * You may use an NMap scan that is integrated with this script to automate finding the CPEs of a target machine and get the information of all CVEs (if any) of the CPEs found by that NMap scan. 

#### Minimum Viable Project Outcomes ####
  * We will be able to take a user's single CPE input and query it against either the vulner's or vuln's databse and get all the CVE's associated with said CPE
  
####  Stretch Goals #####
  * Our script will be able to take different forms of user input such as:
    * Multiple CPE's separated by commas
    * A file (text file or possibly an Excel file) of CPE's
  * Our script will be able to automate finding the CPE's of a given target machine using NMap through Python
  * Our script will be able to save the output (CVE's, description of the CVE, etc.) into an file (Excel file or text file)
