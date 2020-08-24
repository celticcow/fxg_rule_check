#!/usr/bin/python3 -W ignore::DeprecationWarning

import requests
import json
import sys
import time
import ipaddress
import apifunctions
import cgi,cgitb
from packetsearch import packetsearch

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
Greg_Dunlap / CelticCow
FXG Hub rule search

import packetsearch from is_needed // code resuse FTW
"""

def main():
    print("in_function_main")

    debug = 1
    term = "\n"

    #create instance field storage
    form  = cgi.FieldStorage()
    ip1   = "146.18.2.137" #form.getvalue('sourceip')
    ip2   = "10.86.197.165" #form.getvalue('destip')
    port  = "23" #form.getvalue('service')

    ## html header and config data dump
    print ("Content-type:text/html\r\n\r\n")
    print ("<html>", end=term)
    print ("<head>", end=term)
    print ("<title>FXG Rule Search</title>", end=term)
    print ("</head>", end=term)
    print ("<body>", end=term)
    print ("<br><br>", end=term)
    print("FXG Hub Search Search 0.1<br><br>", end=term)

    #policy_search(ip1, ip2, port)
    if(debug == 1):
        print("creating packet search object", end=term)
    search = packetsearch(ip1, ip2, port, "7VRF_FXG-Hub Security", term)
   
    search.create_json_string()
    print(search.get_json(), end=term)

    search.do_search()

    if(debug == 1):
        print("destroying packet search object", end=term)

    print("***** End of Program *****", end=term)
    print("<br><br>")
    print("</body>")
    print("</html>")
#end of main

if __name__ == "__main__":
    main()
#end of program