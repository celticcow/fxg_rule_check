#!/usr/bin/python3 -W ignore::DeprecationWarning

import requests
import json
import sys
import time
import ipaddress
import apifunctions
import cgi,cgitb

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
Greg_Dunlap / CelticCow
"""

def policy_search(source, dest, port):
    debug = 1
    term = "\n"
    mds_ip = "204.135.121.150"
    cma_ip = "204.135.121.164"

    policy="7VRF_FXG-Hub Security"

    packet_mode_json = {
        "name" : policy,
        "filter" : "src:" + source + " AND dst:" + dest + " AND svc:" + port + " AND RulebaseAction:Accept",
        "filter-settings" : {
            "search-mode" : "packet"
        }
    }

    if(debug == 1):
        print(packet_mode_json)
    
    sid = apifunctions.login("roapi", "1qazxsw2", mds_ip, cma_ip)

    if(debug == 1):
        print("session id : " + sid, end=term)
    
    # search here

    pmode_results = apifunctions.api_call(mds_ip, "show-access-rulebase", packet_mode_json, sid)

    if(debug == 1):
        print("------------------------------------", end=term)
        print(json.dumps(pmode_results), end=term)
        print("------------------------------------", end=term)


    time.sleep(10)
    logout_result = apifunctions.api_call(mds_ip, "logout", {}, sid)
    print(logout_result, end=term)
    

def main():
    print("in_function_main")

    debug = 1
    term = "\n"

    #create instance field storage
    form  = cgi.FieldStorage()
    ip1   = "146.18.2.137" #form.getvalue('sourceip')
    ip2   = "10.86.197.165" #form.getvalue('destip')
    port  = "22" #form.getvalue('service')

    ## html header and config data dump
    print ("Content-type:text/html\r\n\r\n")
    print ("<html>", end=term)
    print ("<head>", end=term)
    print ("<title>FXG Rule Search</title>", end=term)
    print ("</head>", end=term)
    print ("<body>", end=term)
    print ("<br><br>", end=term)
    print("FXG Hub Search Search 0.1<br><br>", end=term)

    policy_search(ip1, ip2, port)

    print("***** End of Program *****", end=term)
    print("<br><br>")
    print("</body>")
    print("</html>")
#end of main

if __name__ == "__main__":
    main()
#end of program