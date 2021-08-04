#!/usr/bin/env python3

# WebStor
# 
# Author:
# Ross Geerlings <rjgeer at umich.edu>,  <ross at seekerdlp.com>
#
# Special thanks to:
# Brandon Bailey <Twitter: @ge0stigm4> (Co-designer of original concept) 
# Bob Harold (Guidance on DNS)
# Neamen Negash <nnegash at umich.edu> (Installer)
#
# WebStor uses Wappalyzer's technologies database for pre-populated, name- 
# indexed technology lookups against WebStor's stored responses.  Wappalyzer
# (https://github.com/AliasIO/wappalyzer) is licensed under the terms of the
# MIT licence. 
#
#
#
# WebStor is licensed under the terms of the MIT license, reproduced below.
#
# ==========================================================================

# The MIT License

# Copyright (c) 2020-2021 The University of Michigan Board of Regents. 

# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation fime-les (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
#  

import os
import dns.query
import dns.tsigkeyring
import dns.update
import dns.zone
import sys
import datetime
import requests
from bs4 import BeautifulSoup
import mysql.connector
from multiprocessing.dummy import Pool as ThreadPool
import time
import argparse
import subprocess
import ipaddress
import re
import js_regex
import logging
import urllib3
import urllib.parse
import random
import traceback
import json
import socket
from gevent import Timeout
from gevent import monkey

orig_connect = urllib3.connection.HTTPConnection.connect

parser = argparse.ArgumentParser()
parser.add_argument("--ADD-HTTP-PORT", "-a", dest="HttpPortToAdd", default=None, help="Add a custom HTTP port.")
parser.add_argument("--CLEAR-HTTP", "-aC", dest="ClearHttpPorts", default=False, action="store_true", \
                    help="Clear any custom HTTP ports and revert to default of 80.")
parser.add_argument("--ADD-HTTPS-PORT", "-b", dest="HttpsPortToAdd", default=None, help="Add a custom HTTPS port.")
parser.add_argument("--CLEAR-HTTPS", "-bC", dest="ClearHttpsPorts", default=False, action="store_true", \
                    help="Clear any custom HTTPS ports and revert to default of 443.")
parser.add_argument("--ADD-CUSTOM-FINGERPRINT", "-c", dest="Fingerprint", default=None, \
                    help="Add a custom fingerprint in the form <Name>,<RegEx>.")
parser.add_argument("--DELETE-CUSTOM-FINGERPRINT", "-cD", dest="FingerprintNameToDelete", default=None, \
                    help="Delete a custom fingerprint by name.")
parser.add_argument("--IMPORT-CUSTOM-FINGERPRINT", "-cI", dest="ImportFingerprintFile", default=None, \
                    help="Import a custom fingerprint file with the path specified.")
parser.add_argument("--CLEAR-CUSTOM-FINGERPRINTS", "-cC", dest="ClearFingerprints", default=False, action="store_true", \
                    help="Clears all custom fingerprints stored in DB.")
parser.add_argument("--SHOW-CONFIG", "-g", dest="ShowConfigBrief", default=False, action="store_true", \
                    help="Show current WebStor configuration (brief).")
parser.add_argument("--SHOW-CONFIG-FULL", "-gF", dest="ShowConfigFull", default=False, action="store_true", \
                    help="Show current WebStor configuration (full).")
parser.add_argument("--RUN-MASSCAN", "-m", dest='ForceScan', default=False, action='store_true', \
                    help="Runs a new port scan with Masscan on all configured TCP ports for HTTP and HTTPS, " \
                    "against all configured ranges and any IP addresses from DNS records that are outside those ranges.")
parser.add_argument("--SET-MASSCAN-RANGES", "-mR", dest="SetScanRanges", default=None, \
                    help="Scan range or ranges, replaces existing ranges in DB, comma " \
                    "separated, such as: -s 10.10.0.0/16,10.13.0.0/16,192.168.1.0/24")
parser.add_argument("--IMPORT-MASSCAN-RANGES", "-mI", dest="ImportScanRanges", default=None, \
                    help="Import scan ranges (CIDR blocks) from a specified file.")
parser.add_argument("--DELETE-RANGE", "-mD", dest="RangeToDelete", default=None, help="Delete scan range.")
parser.add_argument("--ADD-PATH", "-p", dest="PathToAdd", default=None, help="Add paths for which to request " \
                    "and store responses besides '/'.")
parser.add_argument("--DELETE-PATH", "-pD", dest="PathToDelete", default=None, help="Delete paths for which to " \
                    "request and store responses besides '/'.")
parser.add_argument("--CLEAR-PATHS", "-pC", dest="ClearPaths", default=False, action="store_true", \
                    help="Clear any custom URL request paths and revert to default of '/'.")
parser.add_argument("--REFRESH-RESPONSES", "-r", dest="RefreshResponses", default=False, action="store_true", \
                    help="Refresh URL responses in DB.")
parser.add_argument("--SEARCH-PATTERN", "-sP", dest="SearchPattern", default=None, \
                    help="Search for string or regular expression in WebStor database.")
parser.add_argument("--SEARCH-CUSTOM-FINGERPRINT", "-sC", dest="SearchFingerprint", default=None, \
                    help="Search for technology by name of user-provided custom fingerprint.")
parser.add_argument("--SEARCH-WAPPALYZER", "-sW", dest="SearchWappalyzer", default=None, \
                    help="Search for technology by name (from Wappalyzer Tech DB) in WebStor DB.")
parser.add_argument("--NO-TSIG-KEY", "-tN", dest="UseTSIG", default=True, action="store_false", \
                    help="Do not use DNSSec TSIG key stored in database or a file, even if present.")
parser.add_argument("--TSIG-KEY-IMPORT", "-tI", dest="ImportTSIGFile", default=None, \
                    help="Import a specified TSIG key file into the database")
parser.add_argument("--TSIG-KEY-REPLACE", "-tR", dest="ReplacementTSIGFile", default=None, \
                    help="Replace a TSIG key in the database with a specified file")
parser.add_argument("--DELETE-TSIG", "-dT", dest="TSIGToDelete", default=None, \
                    help="Delete a TSIG key from the database by name.")
parser.add_argument("--USE-TSIG-FILE-ONLY", "-tF", dest="UseTSIGFileOnly", default=None, \
                    help="Only use tsig file specified (full path), do not use TSIGs stored in the DB. " \
                    "Applies to all domains, limiting WebStor to one TSIG for zone transfers in the current execution.")
parser.add_argument("--DOWNLOAD-NEW-WAPPALYZER", '-w', dest="DLWap", default=False, action="store_true", \
                    help="Download a new Wappalyzer fingerprints file directly from GitHub. Overwrites existing " \
                    "Wappalyzer fingerprint data.")
parser.add_argument("--LIST-WAPPALYZER-TECH-NAMES", "-wL", dest="ListWappalyzer", default=False, action="store_true", \
                    help="List the names of all Wappalyzer technologies in the database.")
parser.add_argument("--ZONE-XFER", "-z", dest='PerformZoneXfer', default=False, action='store_true', \
                    help="Forces a new zone transfer using all domains, servers, and associated TSIG keys in DB")
parser.add_argument("--ADD-DOMAIN", "-zA", dest="DomainDetails", default=None, \
                    help="Add a domain in the form <Domain name>,<Server>,<TSIG Key Name>.")
parser.add_argument("--DELETE-DOMAIN", "-zD", dest="DomainToDelete", default=None, \
                    help="Delete a DNS domain from the database by name.")
parser.add_argument("--IMPORT-ZONE-FILE", "-zI", dest="ImportZoneFile", default=None, \
                    help="Add domains for zone transfers from a file.")
parser.add_argument("--CLEAR-DOMAINS", "-zC", dest="ClearDomains", default=False, action="store_true", \
                    help="Clears all DNS domains stored in DB.")
parser.add_argument("--LIST-DOMAINS", "-zL", dest="ListDomains", default=False, action="store_true", \
                    help="Lists all DNS domains stored in DB.")
parser.add_argument("--SQL-CREDS", "-q", dest="SQLCredsFile", default=None, \
                    help="Use SQL credentials in file at specified path.")

args = parser.parse_args()

sMySQLhost="localhost"
sMySQLuser="root"
sMySQLpw=""

if args.SQLCredsFile != None:
    if os.path.exists(args.SQLCredsFile):
        try:
            MySQLcredFile = open(args.SQLCredsFile, 'r')
            lMySQLlines = MySQLcredFile.readlines()
            sMySQLhost = lMySQLlines[0].rstrip()
            sMySQLuser = lMySQLlines[1].rstrip()
            sMySQLpw = lMySQLlines[2].rstrip()
            mysqlconn = mysql.connector.connect(host=sMySQLhost, user=sMySQLuser, password=sMySQLpw)
        except Exception as e:
            print("Error reading MySQL credential file or connecting to database. Falling back to default credentials." \
                  " Error was: %s\n" % e)
            sMySQLhost="localhost"
            sMySQLuser="root"
            sMySQLpw=""
            try:
                mysqlconn = mysql.connector.connect(host=sMySQLhost, user=sMySQLuser, password=sMySQLpw)
            except Exception as e:
                print("Failed after falling back to default credentials. Exiting. Error was: %s\n\n" \
                      % e)
                exit(1)
    else:
        print("Specified MySQL credential file does not exist. Exiting.")
        exit(1)
    
else:
    try:
        mysqlconn = mysql.connector.connect(host=sMySQLhost, user=sMySQLuser, password=sMySQLpw)
    except Exception as e:
        print("Failed connecting with MySQL default credentials. Exiting. Error was: %s\n\n" \
              "Do you have MariaDB 10.0.5 or newer installed?" % e)
        exit(1)
    
cursor = mysqlconn.cursor()


def create_database():
    #Create the database if it's not already there
    cursor.execute("CREATE DATABASE IF NOT EXISTS webstor")
    #Default latin character set won't work with characters in some responses
    cursor.execute("ALTER DATABASE webstor CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci")
    cursor.execute("USE webstor")
    #tsig keys
    cursor.execute("CREATE TABLE IF NOT EXISTS tsig (name VARCHAR(80), algorithm VARCHAR(80), secret VARCHAR(256), " \
                   "PRIMARY KEY (name))")
    cursor.execute("INSERT IGNORE INTO tsig (name, algorithm, secret) VALUES ('none', 'none', 'none')")
    #Ranges specified by user
    cursor.execute("CREATE TABLE IF NOT EXISTS target_ranges (cidr VARCHAR(18), PRIMARY KEY (cidr))")
    #Domains specified by user
    cursor.execute("CREATE TABLE IF NOT EXISTS domains (domain VARCHAR(80), server VARCHAR(80), keyname VARCHAR(80), " \
                   "PRIMARY KEY (domain))")
    #DNS hosts identified that were outside the target ranges specified by user. These IPs also need to be covered by Masscan
    cursor.execute("CREATE TABLE IF NOT EXISTS dns_hosts (fqdn VARCHAR(80),ip VARCHAR(15), PRIMARY KEY (fqdn,ip))")
    #Paths for which to store responses. Default is '/'
    cursor.execute("CREATE TABLE IF NOT EXISTS paths (path VARCHAR(80), PRIMARY KEY (path))")
    cursor.execute("INSERT IGNORE INTO paths (path) VALUES ('/')")
    #Ports and types. Default 80/HTTP and 443/HTTPS
    cursor.execute("CREATE TABLE IF NOT EXISTS masscan_ports (type VARCHAR(15), port INT, PRIMARY KEY (type,port))")
    cursor.execute("INSERT IGNORE INTO masscan_ports (type,port) VALUES ('http',80)")
    cursor.execute("INSERT IGNORE INTO masscan_ports (type,port) VALUES ('https',443)")
    #Open IP/port combos found by Masscan
    cursor.execute("CREATE TABLE IF NOT EXISTS masscan_results (ip VARCHAR(15), port INT, PRIMARY KEY (ip,port))")
    #Stored responses
    cursor.execute("CREATE TABLE IF NOT EXISTS responses (host VARCHAR(80), port INT, path VARCHAR(80), " \
                   "response LONGTEXT, PRIMARY KEY (host,port))")
    #Imported Wappalyzer technologies database lets us query by technology name against stored responses
    cursor.execute("CREATE TABLE IF NOT EXISTS wapp_technologies (name VARCHAR(80), details VARCHAR(4096), " \
                   "PRIMARY KEY (name))")
    #Custom fingerprints defined by user.  Lets us query by name for a custom regex within responses
    cursor.execute("CREATE TABLE IF NOT EXISTS custom_fingerprints (name VARCHAR(80), regex VARCHAR(4096), " \
                   "PRIMARY KEY (name))")
    #Config values defined by user
    cursor.execute("CREATE TABLE IF NOT EXISTS config (setting VARCHAR(20), value VARCHAR(80), PRIMARY KEY (setting))")
    mysqlconn.commit()
    return


def add_fingerprint(sFingerprint):
    print("Attempting to add custom fingerprint")
    try:
        lFingerprint = sFingerprint.split(',', 1)
    except:
        print("Unable to parse provided fingerprint.  Must be in the form [Name],[Regex].  Provided value was: %s" % \
              sFingerprint)
        return
    print('Importing custom fingerprint with name: "%s" and value: %s' % (lFingerprint[0], lFingerprint[1]))
    sSQL_InsertCF = """INSERT INTO custom_fingerprints (name, regex) VALUES (%s,%s)"""                        
    try:
        cursor.execute(sSQL_InsertCF, (lFingerprint[0],lFingerprint[1]) )
        mysqlconn.commit()
    except Exception as e:
        print("Error inserting values into database: %s", e)
        return
    print("Successfully inserted fingerprint into database.")
    show_config("brief") 
    return


def import_fingerprints(sFileName):
    print("Importing custom fingerprints from file: %s" % sFileName)
    sSQL_InsertCF = """INSERT INTO custom_fingerprints (name, regex) VALUES (%s,%s)"""
    fFingerprintFile = open(sFileName, 'r')
    lFingerprintLines = fFingerprintFile.readlines()
    for sFingerprint in lFingerprintLines:
        try:
            lFingerprint = sFingerprint.split(',', 1)
        except:
            print("File appears to be invalid.  Unable to parse provided fingerprint.  " \
                  "Must be in the form [Name],[Regex].  Provided value was: %s" % sFingerprint)
            return
        print("Inserting fingerprint: %s." % sFingerprint)
        try:
            cursor.execute(sSQL_InsertCF, (lFingerprint[0],lFingerprint[1].rstrip()) )
            mysqlconn.commit()
        except Exception as e:
            print("Error inserting fingerprint values into database: %s", e)
            return
    print("Successfully imported fingerprint(s) into database.")
    show_config("brief") 
    return


def delete_fingerprint(sFingerprintName):
    print("Deleting custom fingerprints.")
    sSQL_DeleteCF = """DELETE FROM custom_fingerprints where name = %s"""
    try:
        cursor.execute(sSQL_DeleteCF, (sFingerprintName,) )
        mysqlconn.commit()
        print("Fingerprint successfully deleted.")
    except Exception as e:
        print("Exception encountered while deleting custom fingerprint from database: %s", e)
        return
    show_config("brief") 
    return


def clear_fingerprints():
    print("Clearing custom fingerprints.")
    try:
        cursor.execute("DROP TABLE IF EXISTS custom_fingerprints")
        cursor.execute("CREATE TABLE IF NOT EXISTS custom_fingerprints (name VARCHAR(80), regex VARCHAR(4096), " \
                   "PRIMARY KEY (name))")
        print("Custom fingerprints successfully cleared.") 
    except Exception as e:
        print("Exception encountered while clearing custom fingerprints from database: %s", e)
        return
    show_config("brief") 
    return


def list_fingerprints():
    print("Custom fingerprints in WebStor database:\n========================================")
    try:
        cursor.execute("SELECT name,regex from custom_fingerprints")
        lCF = cursor.fetchall()
    except Exception as e:
        print("Exception encountered while retrieving custom fingerprints from database: %s", e)
        return
    for Fingerprint in lCF:
        print("Name: %s\nRegex: %s\n------------------------------------------------------------" % Fingerprint)
    return


def perform_masscan():
    lIntRanges = [] #Will be used to store tuples of int representations of net and mask for each range, better performance
    lExtraAddresses = []
    print("Performing Masscan.")
    cursor.execute("DROP TABLE IF EXISTS masscan_results") #IP and port
    cursor.execute("CREATE TABLE IF NOT EXISTS masscan_results (ip VARCHAR(15), port INT, PRIMARY KEY (ip,port))") #IP, port

    #In addition to the ranges provided, we will scan IPs that came up in our zone transfer that are outside the ranges
    #For many organizations, this will be useful as it will look at cloud hosts
    sSQL_SelectIP = "SELECT distinct ip from dns_hosts"
    try:
        cursor.execute(sSQL_SelectIP)
        lIPs = cursor.fetchall()
    except Exception as e:
        print("Exception encountered while retrieving DNS hosts from database: %s", e)
        return
    sSQL_SelectRanges = "SELECT cidr from target_ranges"
    try:
        cursor.execute(sSQL_SelectRanges)
        lRanges = cursor.fetchall()
    except Exception as e:
        print("Exception encountered while retrieving CIDR ranges from database: %s", e)
        return
    print("Retrieved %s IP records from zone transfer(s) and %s target ranges." % (len(lIPs),len(lRanges)))
    print("Checking for DNS records outside of ranges to add to scan...")
    lOriginalRanges = [] #Clean,just string,no tuple
    for tCIDRblock in lRanges:
        lOriginalRanges.append(tCIDRblock[0])
        ip_net = ipaddress.ip_network(tCIDRblock[0]) 
        iNetw = int(ip_net.network_address)
        iMask = int(ip_net.netmask)
        lIntRanges.append((iNetw,iMask))
    for address in lIPs:
        iAddress = int(ipaddress.ip_address(address[0]))
        bInRange = False
        for tIntRange in lIntRanges: 
            bInRange = (iAddress & tIntRange[1]) == tIntRange[0]
            if bInRange == True:
                break
        if bInRange == False:
            lExtraAddresses.append(address[0])
    lExtraAddresses = list(set(lExtraAddresses)) #Only Unique
    print("Total addresses outside ranges added: %s" % len(lExtraAddresses))    
    lAllTargets = lOriginalRanges + lExtraAddresses 
    sAllTargets = ",".join(lAllTargets)
    sSQL_SelectPorts = "SELECT DISTINCT port FROM masscan_ports"
    try:
        cursor.execute(sSQL_SelectPorts)
        lPortTuples = cursor.fetchall()
    except Exception as e:
        print("Exception encountered while retrieving ports from database: %s", e)
        return
    lPorts = []
    for tPorts in lPortTuples:
        lPorts.append(str(tPorts[0]))
    sPorts = ",".join(lPorts)
     
    if len(sAllTargets) > 130000:
        print("WARNING:\n" \
              "The length of the target list appears to exceed the maximum threshold. This usually occurs when an " \
              "organization's network ranges (CIDR blocks) have not all been provided to WebStor. WebStor will now " \
              "attempt to replace all individual RFC1918 private addresses from DNS which share a /24 CIDR block " \
              "with only that block.") \
        #Combine all private addresses with common /24 CIDR blocks into those blocks, eliminating the original.
        lModifiedExtraAddresses = []
        dModifiedExtraAddresses = {}
        for sAddr in lExtraAddresses:
            if ipaddress.ip_address(sAddr).is_private:
                sFirstThreeOctets = sAddr.split('.')
                sThisCIDR = '.'.join(sFirstThreeOctets[:3]) + ".0/24"
                if sThisCIDR in dModifiedExtraAddresses.keys():
                    dModifiedExtraAddresses[sThisCIDR].append(sAddr) 
                else:
                    dModifiedExtraAddresses[sThisCIDR] = [sAddr]
            else:
                lModifiedExtraAddresses.append(sAddr)

        for sCIDR in dModifiedExtraAddresses:
            if len(dModifiedExtraAddresses[sCIDR]) == 1:
                lModifiedExtraAddresses.append(dModifiedExtraAddresses[sCIDR][0])
            else:
                lModifiedExtraAddresses.append(sCIDR)

        lAllTargets = lOriginalRanges + lModifiedExtraAddresses
        sAllTargets = ",".join(lAllTargets)
 
        if len(sAllTargets) > 130000:
            print("WARNING:\n" \
                  "After simplifying private IP address into their shared /24 CIDR blocks, the list of targets is still " \
                  "over the maximum threshold. WebStor will proceed, scanning only the first 6800 specified targets.")
            lAllTargets = lAllTargets[:6800]
        else:
            print("SUCCESS:\n" \
                  "After simplifying private IP address into their shared /24 CIDR blocks, the list of targets is under " \
                  "the maxumum threshold. Proceeding with Masscan...")

        if not os.path.exists('/usr/bin/masscan'):
            print("Could not find /usr/bin/masscan.  Is Masscan installed?")
            exit(1)
         
    MasscanOut = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/masscan', '-p'+sPorts, sAllTargets, '--rate=10000'], stdout=subprocess.PIPE, \
                                  stderr=subprocess.STDOUT)
    stdout,stderr = MasscanOut.communicate()
    lMasscanLines = stdout.decode("ascii").splitlines()
    sPrefixA = "Discovered open port "
    sPrefixB = "tcp on "
    for sLine in lMasscanLines:
        if sLine.startswith(sPrefixA):
            sCurrent = sLine[len(sPrefixA):] 
            aCurrent = sCurrent.split("/")
            if aCurrent[0].isdigit():
                if int(aCurrent[0]) > 1 and int(aCurrent[0]) < 65536:
                    if (aCurrent[1].startswith(sPrefixB)):
                        if is_valid_ipv4(aCurrent[1][len(sPrefixB):]): 
                            sSQL_InsertMSR = """INSERT IGNORE INTO masscan_results (ip, port) VALUES (%s,%s)"""                        
                            cursor.execute(sSQL_InsertMSR, (aCurrent[1][len(sPrefixB):],aCurrent[0]) )
        mysqlconn.commit()
    print("Masscan results have been inserted into WebStor database.")
    return


def show_config(sDetail):
    sDashes = "--------------------------------------------------------------------------------"
    sEquals = "================================================================================"
    print("\n\n")
    print(sEquals)
    print("CURRENT WEBSTOR CONFIG")
    print(sEquals)

    try:
        #Domains (for zone transfers) and count
        sSQL_Select = "SELECT domain from domains"
        cursor.execute(sSQL_Select)
        lDomains = cursor.fetchall()
        sDomains = ', '.join([ str(r[0]) for r in lDomains ]) 
        print("\nDomains:")
        print(sDashes)
        if len(lDomains) > 10 and sDetail == "brief":
            sDomains = ', '.join([ str(r[0]) for r in lDomains[:10] ])
            sDomains += "... (to see full list of configured domains, run WebStor with the -gF switch)."
        else: 
            sDomains = ', '.join([ str(r[0]) for r in lDomains ])
        print(sDomains)
        print(sDashes)
        print("%s total domains configured." % len(lDomains))
    
        #Target ranges and count
        sSQL_Select = "SELECT * from target_ranges"
        cursor.execute(sSQL_Select)
        lRanges = cursor.fetchall()
        if len(lRanges) > 10 and sDetail == "brief":
            sRanges = ', '.join([ str(r[0]) for r in lRanges[:10] ])
            sRanges += "... (to see full list of configured ranges, run WebStor with the -gF switch)."
        else: 
            sRanges = ', '.join([ str(r[0]) for r in lRanges ])
        print("\n\nScan ranges:")
        print(sDashes)
        print(sRanges)
        print(sDashes)
        print("%s total scan ranges configured." % len(lRanges))
    
        #Fingerprints, name and regex, and count
        print("\n\nCustom fingerprints:")
        print(sDashes)
        sSQL_Select = "SELECT name,regex from custom_fingerprints"
        cursor.execute(sSQL_Select)
        lCustom = cursor.fetchall()
        for Fingerprint in lCustom:
            print("Name: %-20s    Regex: %s" % Fingerprint)
        print(sDashes)
        print("%s custom fingerprints in database." % len(lCustom))
    
        #Paths and count
        print("\n\nPaths against which HTTP and HTTPS request are performed:")
        sSQL_Select = "SELECT path from paths" 
        cursor.execute(sSQL_Select)
        lPaths = cursor.fetchall()
        print(sDashes)
        for path in lPaths:
            print(path[0])
        print(sDashes)
        sSQL_Select = "SELECT COUNT(*) from paths"
        cursor.execute(sSQL_Select)
        lPath = cursor.fetchall()
        print("%s total path(s) in database." % str(lPath[0][0]))
    
        #TSIGs and count
        print("\n\nNames of TSIG keys in database:")
        sSQL_Select = "SELECT name from tsig where name not like 'none'"
        cursor.execute(sSQL_Select)
        lTSIGs = cursor.fetchall()
        sTsigNames = ', '.join([ str(r[0]) for r in lTSIGs ]) 
        sTSIGs = ', '.join([ str(r[0]) for r in lTSIGs ])
        print(sDashes)
        print(sTSIGs)
        print(sDashes)
        sSQL_Select = "SELECT COUNT(*) from tsig where name not like 'none'"
        cursor.execute(sSQL_Select)
        lTSIG = cursor.fetchall()
        print("%s total TSIG key(s) in database." % str(lTSIG[0][0]))
    
        #HTTP ports, HTTPS ports, Present count of Wappalyzer technologies, and number of stored responses
        sSQL_Select = "SELECT port from masscan_ports where type='http'"
        cursor.execute(sSQL_Select)
        sHttp = ', '.join([ str(r[0]) for r in cursor.fetchall() ]) 
        print("\n\nHTTP ports: %s" % sHttp)
    
        sSQL_Select = "SELECT port from masscan_ports where type='https'"
        cursor.execute(sSQL_Select)
        sHttps = ', '.join([ str(r[0]) for r in cursor.fetchall() ]) 
        print("HTTPS ports: %s" % sHttps)
    
        sSQL_Select = "SELECT COUNT(*) from wapp_technologies"
        cursor.execute(sSQL_Select)
        lWapp = cursor.fetchall()
        print("Number of Wappalyzer technologies in database: %s" % str(lWapp[0][0]))
    
        sSQL_Select = "SELECT COUNT(*) from responses"
        cursor.execute(sSQL_Select)
        lResp = cursor.fetchall()
        print("Number of responses in database: %s" % str(lResp[0][0]))
    except Exception as e:
        print("\nException encountered while retrieving configuration settings from database: %s", e)
        return
    print(sEquals)
    print("\n\n")
    return


def add_http_port(sPort):
    if not sPort.isdigit():
        print("Port value is not an integer.")
        return
    if int(sPort) < 1 or int(sPort) > 65535:
        print("Port is outside valid range.")
        return
    sInsertPort = """INSERT IGNORE INTO masscan_ports (type,port) VALUES (%s,%s)"""
    print("Attempting to add HTTP port: %s." % sPort)
    try:
        cursor.execute(sInsertPort, ('http',int(sPort)) )
        mysqlconn.commit()
    except Exception as e:
        print("Exception encountered inserting ports into database: %s", e)
        return
    print("Successfully added HTTP port to database.")
    show_config("brief")
    return


def clear_http_ports():
    print("Attempting to clear HTTP Ports.")
    try:
        cursor.execute("DELETE FROM masscan_ports WHERE type='http'")
        cursor.execute("INSERT IGNORE INTO masscan_ports (type,port) VALUES ('http',80)")
        mysqlconn.commit()
    except Exception as e:
        print("Exception encountered clearing HTTP ports from database: %s", e)
        return
    show_config("brief")
    return


def add_https_port(sPort):
    if not sPort.isdigit():
        print("Port value is not an integer.")
        return
    if int(sPort) < 1 or int(sPort) > 65535:
        print("Port is outside valid range.")
        return
    sInsertPort = """INSERT IGNORE INTO masscan_ports (type,port) VALUES (%s,%s)"""
    print("Attempting to add HTTPS port: %s." % sPort)
    try:
        cursor.execute(sInsertPort, ('https',int(sPort)) )
        mysqlconn.commit()
    except Exception as e:
        print("Exception encountered inserting ports into database: %s", e)
        return
    print("Successfully added HTTPS port to database.")
    show_config("brief")
    return


def clear_https_ports():
    print("Attempting to clear HTTPS Ports.")
    try:
        cursor.execute("DELETE FROM masscan_ports WHERE type='https'")
        cursor.execute("INSERT IGNORE INTO masscan_ports (type,port) VALUES ('https',443)")
        mysqlconn.commit()
    except Exception as e:
        print("Exception encountered clearing HTTPS ports from database: %s", e)
        return
    show_config("brief")
    return


def add_path(sPath):
    print("Attempting to add path: %s" % sPath)
    if not sPath.startswith("/") and not sPath.startswith("?"):
        print("Any request path should start with '/' or '?'.  Not adding.")
        return
    sPath = sPath.replace("'","''")
    sInsertPath = """INSERT IGNORE INTO paths (path) VALUES (%s)"""
    try:
        cursor.execute(sInsertPath, (sPath,) )
        mysqlconn.commit()
    except Exception as e:
        print("Error inserting path value into database: %s", e)
    show_config("brief")
    return


def delete_path(sPathToRemove):
    print("Attempting to remove path: %s" % sPathToRemove)
    sDeletePath = """DELETE FROM paths WHERE path = %s""" 
    try:
        cursor.execute(sDeletePath, (sPathToRemove,) )
        mysqlconn.commit()
    except Exception as e:
        print("Error deleting path value from database: %s", e)
        return
    show_config("brief")
    return


def clear_paths():
    print("Attempting to clear paths.")
    try:
        cursor.execute("DELETE FROM paths")
        cursor.execute("INSERT IGNORE INTO paths (path) VALUES ('/')")
        mysqlconn.commit()
    except Exception as e:
        print("Error clearing path values from database: %s", e)
        return
    show_config("brief")
    return


def patch_connect(self):
    orig_connect(self)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
    self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1),
    self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3),
    self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5),
    return


def refresh_responses():
    print ("Refreshing responses for targets from most recent Masscan.")
    #Get the list of requests we need to make. Start with Masscan responses
    try:
        sSQL_Select_dnsh = "SELECT * from dns_hosts"
        cursor.execute(sSQL_Select_dnsh)
        lDNSh = cursor.fetchall()
    except Exception as e:
        print("Error retrieving DNS host values from database: %s", e)
        return
    #Dictionary for faster, easier lookup
    dDNSh = {}
    for tDNSh in lDNSh:
        if tDNSh[1] not in dDNSh:
            dDNSh[tDNSh[1]] = [tDNSh[0]]
        else:
            dDNSh[tDNSh[1]].append(tDNSh[0])
    print("Name table completed with one or more names mapped to %s IPs." % len(dDNSh)) 

    sSQL_Select_ports = "SELECT * from masscan_ports"
    try:
        cursor.execute(sSQL_Select_ports)
    except Exception as e:
        print("Error retrieving ports from database: %s", e)
        return
    lPorts = []
    lPorts = cursor.fetchall()
    dPorts = {}
    for tPort in lPorts:
        dPorts[tPort[1]] = tPort[0]

    sSQL_Select_Paths = "SELECT * from paths"
    try:
        cursor.execute(sSQL_Select_Paths)
    except Exception as e:
        print("Error retrieving paths from database: %s", e)
        return
    lPaths = cursor.fetchall()

    lRequests = []
    sSQL_Select_mr = "SELECT * from masscan_results"
    try:
        cursor.execute(sSQL_Select_mr)
    except Exception as e:
        print("Error retrieving Masscan results from database: %s", e)
        return
    lMR = cursor.fetchall() #[0] is IP, [1] is port
    iTotalRequests = 0
    iTotalExceptions = 0
    iTotalInsertions = 0
    for tMSresult in lMR:
        for tPath in lPaths: 
            sRequest = dPorts[tMSresult[1]]+"://"+tMSresult[0].rstrip()
            if (tMSresult[1] != 80) and (tMSresult[1] != 443):
                sRequest += ":" + str(tMSresult[1]) 
            sRequest += tPath[0] 
            lRequests.append((sRequest,tMSresult[0].rstrip(),tMSresult[1],tPath[0]))
            iTotalRequests +=1
            try:
                for sHostname in dDNSh[tMSresult[0].rstrip()]:
                    sRequest = dPorts[tMSresult[1]]+"://"+sHostname
                    if (tMSresult[1] != 80) and (tMSresult[1] != 443):
                        sRequest += ":" + str(tMSresult[1]) 
                    sRequest += tPath[0] 
                    lRequests.append((sRequest,sHostname,tMSresult[1],tPath[0]))
                    iTotalRequests +=1
            except KeyError:
                continue

    try:
        cursor.execute("DROP TABLE IF EXISTS responses") 
        cursor.execute("CREATE TABLE IF NOT EXISTS responses (host VARCHAR(80), port INT, path VARCHAR(80), " \
                       "response LONGTEXT, PRIMARY KEY (host,port))")
    except Exception as e:
        print("Error dropping and recreating responses table: %s", e)
        return

    print("Using threadpool for %s requests (this may take some time) ..." % iTotalRequests)
    random.shuffle(lRequests)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    urllib3.connection.HTTPConnection.connect = patch_connect
    sSQL_InsertResponse = """INSERT INTO responses (host,port,path,response) VALUES (%s,%s,%s,%s)"""
    start_time = time.time()
    pool = ThreadPool(128)
    lResults = pool.map(url_request, lRequests)
    lResults= list(filter(None, lResults))
    iCumulativeSize = 0
    try:
        cursor.execute("SET GLOBAL max_allowed_packet=2048000000")
        mysqlconn.commit()
    except Exception as e:
        print("Error resetting max packet size: %s", e)
        return

    print("Beginning database insertions.")
    for tResult in lResults:
        if tResult != None:
            try:
                cursor.execute(sSQL_InsertResponse, tResult) 
                iTotalInsertions += 1
            except Exception as e:
                iTotalExceptions += 1
                logging.debug("Problem inserting response record beginning with %s,%s,%s,%s: " % \
                              (tResult[0], tResult[1], tResult[2], tResult[3][:128], e) )
                logging.debug(traceback.format_exc()) 
            iCumulativeSize += len(str(tResult))
        if iTotalInsertions % 10 == 0:
            try:
                mysqlconn.commit()
            except Exception as e:
                print("Error committing response insertions to database: %s", e)
                return
            iCumulativeSize = 0
    try:
        mysqlconn.commit()
    except Exception as e:
        print("Error committing response insertions to database: %s", e)
        return
    pool.close()
    pool.join()
    print("%s exceptions encountered during database insertions." % iTotalExceptions)
    print("%s total insertions made in %s seconds." % (iTotalInsertions,format(time.time() - start_time,'.2f')))
    return


def set_scan_ranges(sScanRanges):
    print("Attempting to set scan ranges to: %s" % sScanRanges)
    sInsertRange = """INSERT IGNORE INTO target_ranges (cidr) VALUES (%s)"""
    lScanRanges = sScanRanges.split(',')
    for sCIDRblock in lScanRanges:
        print(sCIDRblock)
        lCIDRblock = sCIDRblock.split('/')
        if lCIDRblock[1].isdigit():
            if (len(lCIDRblock)==2) and (is_valid_ipv4(lCIDRblock[0])) and (int(lCIDRblock[1])>7 and int(lCIDRblock[1])<33):
                print("Inserting CIDR block: %s." % sCIDRblock.rstrip() )
                try:
                    cursor.execute(sInsertRange, (sCIDRblock.rstrip(),) ) 
                    mysqlconn.commit()
                except Exception as e:
                    print("Error inserting scan ranges into database: %s", e)
                    return
            else:
                print(len(lCIDRblock))
                print(is_valid_ipv4(lCIDRblock[0]))
                print(int(lCIDRblock[1]))
                print("Invalid CIDR block: %s. Exiting." % sCIDRblock)
                exit(1)
        else:
            print("Invalid bit mask for CIDR block: %s. Exiting." % sCIDRblock)
            exit(1)
    print("Successfully inserted scan ranges into database.")
    return


def import_scan_ranges(sFileName):
    print("Attempting to import scan ranges from file: %s" % sFileName)
    sInsertRange = """INSERT IGNORE INTO target_ranges (cidr) VALUES (%s)"""
    lScanRangeLines = [] 

    try:
        fScanRangeFile = open(sFileName, 'r') 
        lScanRangeLines = fScanRangeFile.readlines()
    except Exception as e:
        print("Error opening file for scan range import: %s", e)
        return
    for sCIDRblock in lScanRangeLines:
        lCIDRblock = sCIDRblock.split('/')
        if (len(lCIDRblock) == 2) and (is_valid_ipv4(lCIDRblock[0])) and (int(lCIDRblock[1])>7 and int(lCIDRblock[1])<33):
            print("Inserting CIDR block: %s." % sCIDRblock.rstrip())
            try:
                cursor.execute(sInsertRange, (sCIDRblock.rstrip(),)) 
                mysqlconn.commit()
            except Exception as e:
                print("Error inserting scan ranges into database: %s", e)
                return
        else:
            print("Skipping invalid CIDR block in file: %s" % sCIDRblock )
    print("Successfully imported scan ranges into database.")
    return


def delete_scan_range(sRangeToRemove):
    print("Attempting to delete scan range: %s" % sRangeToRemove)
    sql_delete_range = """DELETE FROM target_ranges WHERE cidr = %s""" 
    try:
        cursor.execute(sql_delete_range, (sRangeToRemove,) )
        mysqlconn.commit()
    except Exception as e:
        print("Error deleting range: %s" % e)
        return
    print("Successfully deleted range.")
    show_config("brief")
    return


def import_tsig(sFileName):
    print("Attempting to import TSIG file: %s" % sFileName)
    #Key name, algorithm, secret
    sDomain = input("Enter a domain(s) to associate with this TSIG, comma separate if more than one: ")
    sDomain = sDomain.replace(" ", "")
    aDomains = sDomain.split(",")
    sServer = input("Enter a DNS server IP address to associate with domain(s) and TSIG: ") 
    if not is_valid_ipv4(sServer):
        print("DNS server must be given as a valid IPv4 IP address.  Exiting.")
        exit(1)
    print("Those values are %s %s" % (aDomains, sServer))
    try:
        TSIGFile = open(sFileName, 'r') 
        aTSIGLines = TSIGFile.readlines()
        if aTSIGLines[0].startswith("key"):
            sKey = aTSIGLines[0].split()[1]
            print(sKey)
        else:
            print("Invalid key name in TSIG file")
            return
        if aTSIGLines[1].find("algorithm"):
            sAlgorithm = aTSIGLines[1].split('"')[1]
            print(sAlgorithm)
        else:
            print("Invalid algorithm in TSIG file")
            return
        if aTSIGLines[2].find("secret"):
            sSecret = aTSIGLines[2].split('"')[1]
            print(sSecret)
        else:
            print("Invalid secret in TSIG file")
            return
    except Exception as e:
        print("Error importing TSIG from file: %s", e)
        return

    sInsertTsig = """INSERT INTO tsig (name, algorithm, secret) VALUES (%s,%s,%s)""" 
    try:
        cursor.execute(sInsertTsig, (sKey,sAlgorithm,sSecret) )
        mysqlconn.commit()
    except Exception as e:
        print("Error inserting scan ranges into database: %s", e)
        return

    #loop through each domain that was provided...
    sInsertDomain = """INSERT INTO domains (domain, server, keyname) VALUES (%s,%s,%s)""" 
    try:
        for sDomain in aDomains: 
            tDomainInsert = (sDomain,sServer,sKey)
            cursor.execute(sInsertDomain, tDomainInsert) 
            mysqlconn.commit()
    except Exception as e:
        print("Error inserting scan ranges into database: %s", e)
        return
    print("Successfully inserted TSIG into database.")
    show_config("brief")
    return


def replace_tsig(sFileName):
    #Key name, algorithm, secret
    print("Attempting to import TSIG file, overwriting any previous key with same name: %s" % sFileName)
    try:
        TSIGFile = open(sFileName, 'r') 
        aTSIGLines = TSIGFile.readlines()
    except Exception as e:
        print("Error opening TSIG file: %s", e)
        return
    if aTSIGLines[0].startswith("key"):
        sKey = aTSIGLines[0].split()[1]
    else:
        print("Invalid key name in TSIG file")
        return
    if aTSIGLines[1].find("algorithm"):
        sAlgorithm = aTSIGLines[1].split('"')[1]
    else:
        print("Invalid algorithm in TSIG file")
        return
    if aTSIGLines[2].find("secret"):
        sSecret = aTSIGLines[2].split('"')[1]
    else:
        print("Invalid secret in TSIG file")
        return

    sql_insert="INSERT INTO tsig (name,algorithm,secret) VALUES (%s,%s,%s) ON DUPLICATE KEY UPDATE algorithm=%s, secret=%s" 
    tTsigInsert = (sKey,sAlgorithm,sSecret,sAlgorithm,sSecret)
    logging.debug(tTsigInsert)
    try:
        cursor.execute(sql_insert, tTsigInsert)
        mysqlconn.commit()
    except Exception as e:
        print("Error replacing TSIG file: %s", e)
        return
    print("Successfully replaced TSIG.")
    show_config("brief")
    return


def delete_tsig(sTSIGToRemove):
    print("Attempting to remove domains using TSIG named: %s" % sTSIGToRemove)
    try:
        sql_delete_domain = """DELETE FROM domains WHERE keyname = '%s')""" 
        cursor.execute(sql_delete_domain, (sTSIGToRemove,) )
        mysqlconn.commit()
    except Exception as e:
        print("Error deleting domains associated with this key: %s" % e)
        return
    print("Attempting to remove TSIG Key: %s" % sTSIGToRemove)
    try:
        sql_delete_tsig = """DELETE FROM tsig WHERE name = '%s')""" 
        cursor.execute(sql_delete_tsig, (sTSIGToRemove,) )
        mysqlconn.commit()
    except Exception as e:
        print("Error deleting TSIG key from database: %s" % e)
        return
    print("Successfully deleted TSIG.")
    show_config("brief")
    return


def add_domain(sDomainToAdd):
    print("Attempting to add domain: %s", sDomainToAdd)
    try:
        lDomainToAdd = sDomainToAdd.split(',', 2)
    except:
        print("Unable to parse provided domain. Must be in the form <Domain name>,<Server>,<TSIG Key Name>. " \
              "Provided value was: %s" % sDomainToAdd)
        return
    print("Domain: %s" % lDomainToAdd[0])
    print("Server: %s" % lDomainToAdd[1])
    print("TSIG key name: %s" % lDomainToAdd[2])

    try:
        if lDomainToAdd[2] == 'none':
            lTSIG = ['none']
        else:
            sSQL_Select_tsig = "Select * from tsig where name = %s"
            cursor.execute(sSQL_Select_tsig, (lDomainToAdd[2],))
            lTSIG = cursor.fetchall()
    except Exception as e:
        print("Error reading TSIG keys from database: %s" % e)
        return
    
    if len(lTSIG) < 1:
        print ("No match found for specified TSIG name.")
        return

    if (not is_valid_hostname(lDomainToAdd[0])):
        print("The domain name provided is not valid. Aborting.")
        return
    if (not is_valid_ipv4(lDomainToAdd[1])) and (not is_valid_hostname(lDomainToAdd[1])):
        print("The DNS Server name provided is not a valid name or IP. Aborting.")
        return

    print('Adding domain with name: "%s", server: %s, and key name: %s' % (lDomainToAdd[0],lDomainToAdd[1],lDomainToAdd[2]))
    sInsertDomain = """INSERT INTO domains (domain, server, keyname) VALUES (%s,%s,%s)"""
    try:
        cursor.execute(sInsertDomain, (lDomainToAdd[0],lDomainToAdd[1],lDomainToAdd[2]) )
        mysqlconn.commit()
    except Exception as e:
        print("Error inserting domain values into database: %s" % e)
        return
    print("Successfully inserted domain into database.")
    show_config("brief") 
    return


def download_wappalyzer():
    print("Downloading Wappalyzer Fingerprints from GitHub Repo.")
    sWappalyzerResponse = ""
    try:
        r = requests.get("https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json", \
                         timeout=5)
        sWappalyzerResponse = str(r.text)
    except:
        print("Wappalyzer technologies json file not available.")

    try:
        cursor.execute("DROP TABLE IF EXISTS wapp_technologies")
        cursor.execute("CREATE TABLE IF NOT EXISTS wapp_technologies (name VARCHAR(80), details VARCHAR(4096), " \
                       "PRIMARY KEY (name))")
        dWappalyzer = json.loads(sWappalyzerResponse) 
        dTechnologies = dWappalyzer.get('technologies')
        sInsertWappTech = """INSERT IGNORE INTO wapp_technologies (name, details) VALUES (%s,%s)""" 
        for sName in dTechnologies:
            cursor.execute(sInsertWappTech, (sName.rstrip(),str(dTechnologies.get(sName)).rstrip()) ) 
        mysqlconn.commit()
    except Exception as e:
        print("Error inserting Wappalyzer data: %s" % e)
        return
    print("Successfully inserted Wappalyzer fingerprints into database.")
    show_config("brief") 
    return


def list_wappalyzer():
    print("\nNames of Wappalyzer technologies in database:")
    print("---------------------------------------------")
    sSQL_Select = "SELECT name from wapp_technologies" 
    try:
        cursor.execute(sSQL_Select)
        lTechs = cursor.fetchall()
        for sTech in lTechs:
            print(sTech[0])
    except Exception as e:
        print("Error listing Wappalyzer technologies: %s" % e)
    return


def search_pattern(sSearchPattern):
    sSQL_Search_Responses = "SELECT host FROM responses WHERE response REGEXP %s"
    start_time = time.time()
    try:
        cursor.execute(sSQL_Search_Responses,(sSearchPattern,) )
        Response_records = cursor.fetchall()
    except Exception as e:
        print("Error querying search pattern: %s" % e)
        return
    if len(Response_records) > 0:
        for tRespondingURL in Response_records:
            print(tRespondingURL[0])
        sTime = format(time.time() - start_time,'.2f')
        print('%s total URLs have reponses containing the string "%s" returned in %s seconds.' % (len(Response_records), \
              sSearchPattern, sTime))
    else:
        print("No matches found.")
    return


def search_fingerprint(sFingerprintName):
    sSQL_Search_Fingerprints = "SELECT regex from custom_fingerprints WHERE name like %s"  
    try:
        cursor.execute(sSQL_Search_Fingerprints, ("%"+sFingerprintName+"%",) )
        Fingerprints_records = cursor.fetchall()
    except Exception as e:
        print("Error querying search fingerprint name: %s" % e)
        return
    if len(Fingerprints_records) > 0:
        query_start_time = time.time()
        sSQL_Search_Responses = "Select host from responses where response REGEXP %s"
        try:
            cursor.execute(sSQL_Search_Responses, (Fingerprints_records[0][0],) )
            Matching_responses = cursor.fetchall()
        except Exception as e:
            print("Error querying responses for fingerprint: %s" % e)
            return
        print("Matching URLS:")
        for url in Matching_responses:
            print(url[0])
        print("--- %s matching URLs found for %s in %s seconds. ---" % (len(Matching_responses), sFingerprintName, \
              format(time.time() - query_start_time,'.2f')))
    else:
        print("No custom fingerprints in the database match the name '%s'" % sFingerprintName)
    return


def search_wappalyzer(sSearchName):
    TupleToRegexCheck = ()
    ListToRegexCheck = []

    sSQL_Search_Technologies = "SELECT details FROM wapp_technologies WHERE name like %s"
    try:
        cursor.execute(sSQL_Search_Technologies, ("%"+sSearchName+'%',) )
        Technologies_records = cursor.fetchall()
    except Exception as e:
        print("Error searching Wappalyzer tachnologies: %s" % e)
        return
    if len(Technologies_records) > 0:
        p = re.compile('(?<!\\\\)\'')
        sWappalyzerTech = Technologies_records[0][0].replace("\"", "\\\"")
        sWappalyzerTech = sWappalyzerTech.replace("\\'","\\\\'")
        sWappalyzerTech = p.sub('\"', sWappalyzerTech)
        sWappalyzerTech = re.sub(r'":\ (True|False),', '": "",', sWappalyzerTech)
        dWappalyzerTech = json.loads(sWappalyzerTech)

        #For meta in wappalyzer technologies, they are regex but we have to format each one we get.
        #We'll do that and add directly to the tuple now. 
        if "meta" in dWappalyzerTech.keys():
            if isinstance(dWappalyzerTech.get("meta"), dict):
                for key in dWappalyzerTech["meta"]:
                    if ";confidence:" not in dWappalyzerTech["meta"][key]:
                        ListToRegexCheck.append("<meta name=[\"\']%s[\"\'] content=[\"\']%s" % (key, \
                                                dWappalyzerTech["meta"][key].strip('^').strip('$')))
        if "html" in dWappalyzerTech.keys():
            if isinstance(dWappalyzerTech.get("html"), str):
                if ";confidence:" not in dWappalyzerTech.get("html"):
                    ListToRegexCheck.append(dWappalyzerTech.get("html"))
            if isinstance(dWappalyzerTech.get("html"), list):
                for sHTMLreg in dWappalyzerTech.get("html"):
                    if ";confidence:" not in sHTMLreg:
                        ListToRegexCheck.append(sHTMLreg)
        if "scripts" in dWappalyzerTech.keys():
            if isinstance(dWappalyzerTech.get("scripts"), str):
                if ";confidence:" not in dWappalyzerTech.get("scripts"):
                    ListToRegexCheck.append(dWappalyzerTech.get("scripts"))
            if isinstance(dWappalyzerTech.get("scripts"), list):
                for sScriptreg in dWappalyzerTech.get("scripts"):
                    if ";confidence:" not in sScriptreg:
                        ListToRegexCheck.append(sScriptreg)
        if "icon" in dWappalyzerTech.keys():
            if isinstance(dWappalyzerTech.get("icon"), str):
                if ";confidence:" not in dWappalyzerTech.get("icon"):
                    ListToRegexCheck.append("\\b%s\\b" % dWappalyzerTech.get("icon"))
        if "cookies" in dWappalyzerTech.keys():
                for key in dWappalyzerTech["cookies"]:
                    if ";confidence:" not in dWappalyzerTech["cookies"][key]:
                        sRegexToAdd = "%s=" % key
                        if len(dWappalyzerTech["cookies"][key]) > 0:
                            sRegexToAdd += dWappalyzerTech["cookies"][key]
                        ListToRegexCheck.append(sRegexToAdd)
        if "headers" in dWappalyzerTech.keys():
                for key in dWappalyzerTech["headers"]:
                    if ";confidence:" not in dWappalyzerTech["headers"][key]:
                        sRegexToAdd = "%s:\\ " % key
                        if len(dWappalyzerTech["headers"][key]) > 0:
                            sRegexToAdd += dWappalyzerTech["headers"][key]
                        ListToRegexCheck.append(sRegexToAdd)
        if len(ListToRegexCheck) > 0:
            #Move into tuple format
            TupleToRegexCheck = tuple(ListToRegexCheck) 

            #format query 
            query_start_time = time.time()
            i=0
            sSQL_Search_Responses = "Select host from responses where "
            for sRegexForQuery in ListToRegexCheck:
                if i > 0:
                    sSQL_Search_Responses += " OR"
                sSQL_Search_Responses += " response REGEXP %s"
                i += 1

            #For every item in the database, does it match this technology
            try:
                cursor.execute(sSQL_Search_Responses,TupleToRegexCheck)
                Matching_responses = cursor.fetchall()
            except Exception as e:
                print("Error searching Wappalyzer tachnologies in responses: %s" % e)
                return
            #print(Matching_responses)
            for url in Matching_responses:
                print(url[0])
            print("--- %s matching URLs found for %s in %s seconds. ---" % (len(Matching_responses), sSearchName, \
                  format(time.time() - query_start_time,'.2f')))
        else:
            print("The technology you specified did not provide any items for which to query (or they all were of " \
                  "limited confidence).")
    else:
        print("No technologies in the database match the name '%s'" % sSearchName)
    return


def url_request(tTarget):
    sURL = tTarget[0]
    sHost = tTarget[1]
    iPort = tTarget[2]
    sPath = tTarget[3]
    r = None
    try:
        print("Attempting:" + sURL)
        try:
            timeout = Timeout(8)
            timeout.start()
            r = requests.get(sURL,  verify=False, timeout=3)
        except Timeout as T:
            print("***Python requests.get() hung for URL %s." % sURL)
            return
        if r is None:
            return
        print("Done:      " + sURL)
        try:
            return ((sURL,iPort,sPath,str(r.headers)+"\n"+str(r.text)[:4096000]))
        except:
            print("Unable to return response for insertion into database.")
    except:
        print("Site down: " + sURL)


def find_list_resources(tag, attribute, soup):
    list = []
    for x in soup.findAll(tag):
        try:
            list.append(x[attribute])
        except KeyError:
            pass
    return list


def dns_zone_xfer(sTSIGfile):
    print("Attempting zone transfer for domains in database.")
    sZoneXfersQuery = "SELECT domains.domain as zone, domains.server as server, domains.keyname as keyname, " \
                      "tsig.algorithm as algorithm, tsig.secret FROM domains INNER JOIN tsig ON domains.keyname = tsig.name"
    try: 
        cursor.execute("DROP TABLE IF EXISTS dns_hosts")
        cursor.execute("CREATE TABLE IF NOT EXISTS dns_hosts (fqdn VARCHAR(80),ip VARCHAR(15), PRIMARY KEY (fqdn,ip))")
    except Exception as e:
        print("Error dropping and recreating DNS hosts table: %s" %  e)
        return
    sSQL_Select_TSIG = "select * from tsig"
    sSQL_Select_domains = "select * from domains"
    sInsertHost = """INSERT IGNORE INTO dns_hosts (fqdn, ip) VALUES (%s,%s)"""
    try:
        cursor.execute(sSQL_Select_TSIG)
        TSIG_records = cursor.fetchall()
        cursor.execute(sSQL_Select_domains)
        Domain_records = cursor.fetchall()
    except Exception as e:
        print("Error retrieving TSIG keys and/or domains from database: %s" %  e)
        return
    print("Total number of rows in tsig is: ", cursor.rowcount)
    print("Total number of rows in domains is: ", cursor.rowcount)

    dArecords = {}
    dCNAMErecords = {}
    iTotalMappings = 0
    iCNAMEsmapped = 0
    iZonesTransferred = 0

    #Inner join TSIG and Zone tables so we can grab the right key for each domain.
    cursor.execute(sZoneXfersQuery)
    lZoneInfo = cursor.fetchall()

    for tZoneInfo in lZoneInfo:
        sZone = tZoneInfo[0]
        sServer = tZoneInfo[1]
        if sTSIGfile == None:
            sKeyName = tZoneInfo[2]
            sAlgorithm = tZoneInfo[3]
            sSecret = tZoneInfo[4]
        else:
            #If the file-based tsig has been specified, take the values out of the file.
            try:
                TSIGFile = open(sTSIGfile, 'r')
                aTSIGLines = TSIGFile.readlines()
            except Exception as e:
                print("Error opening TSIG file %s: %s" % (sZone, e))
                return
            if aTSIGLines[0].startswith("key"):
                sKeyName = aTSIGLines[0].split()[1]
            else:
                print("Invalid key name in TSIG file")
                return
            if aTSIGLines[1].find("algorithm"):
                sAlgorithm = aTSIGLines[1].split('"')[1]
            else:
                print("Invalid algorithm in TSIG file")
                return
            if aTSIGLines[2].find("secret"):
                sSecret = aTSIGLines[2].split('"')[1]
            else:
                print("Invalid secret in TSIG file")
                return

        try:
            print("Now transferring zone: %s" % sZone)
            logging.debug("Now transferring zone: %s" % sZone)
            if sKeyName == 'none':
                xfr = dns.query.xfr(sServer, sZone, port=53, keyring=None, keyname=None, keyalgorithm=None)
            else: 
                mykeyring = dns.tsigkeyring.from_text({sKeyName: sSecret}) #name and secret
                xfr = dns.query.xfr(sServer, sZone, port=53, keyring=mykeyring, keyname=sKeyName, keyalgorithm=sAlgorithm)
            zone = dns.zone.from_xfr(xfr, check_origin=False)
            names = zone.nodes.keys()
            for n in names:
                sDNSRecord = zone[n].to_text(n)
                sFQDN = sDNSRecord.split()[0] + "." + sZone 
                sRecordValue = sDNSRecord.split()[4] 
                sType = sDNSRecord.split()[3] 
                if ( not sFQDN.startswith('*') ) and (sRecordValue != '127.0.0.1'):
                    if sType == 'A': 
                        logging.debug("Adding IP record for A record: %s, %s" % (sFQDN,sRecordValue))
                        tHostInsert = (sFQDN,sRecordValue) 
                        cursor.execute(sInsertHost, tHostInsert)
                        dArecords[sFQDN] = sRecordValue
                        iTotalMappings += 1 
                    if sType == 'CNAME':
                        dCNAMErecords[sFQDN] = sRecordValue + "." + sZone
            iZonesTransferred += 1 
        except Exception as e:
            print("Error transferring zone %s: %s" % (sZone, e))
    mysqlconn.commit()

    #Take care of CNAMEs.  Map them directly to their IPs
    print("Done transferring zones.  Creating IP mapping table.")
    for sAlias in dCNAMErecords:
        sIP = dArecords.get(sAlias)
        if sIP != None:
            logging.debug("Adding IP record for CNAME: %s, %s" % (sAlias,sIP))
            tHostInsert = (sAlias,sIP)
            cursor.execute(sInsertHost, tHostInsert)
            iCNAMEsmapped += 1 
            iTotalMappings += 1 

        #We will also map things that have two levels of aliasing to their IPs 
        else:
            sSecondLevelAlias =  dCNAMErecords.get(sAlias)
            if sSecondLevelAlias != None:
                sIP = dArecords.get(sSecondLevelAlias)
                if sIP != None:
                    tHostInsert = (sAlias,sIP)
                    cursor.execute(sInsertHost, tHostInsert)
                    iCNAMEsmapped += 1 
                else:
                    logging.debug("After two levels of aliases, we did not have a host record for %s." % sAlias)
            else:
                logging.debug("The alias '%s' did not point to a host record or second-level alias withon our configured " \
                              "zones." % sAlias)
    mysqlconn.commit()

    print("IP mapping complete.")
    print("================================================================================")
    print("Total zones transferred: %s" % iZonesTransferred)
    print("Total indirect (CNAME) mappings resolved to IP addresses: %s" % iCNAMEsmapped)
    print("Total direct or indirect (host or CNAME) mappings to IP addresses: %s" % iTotalMappings)
    return


def import_zones_from_file(sFileName):
    print("Attempting to import domains from file: %s" % sFileName)
    ZoneFile = open(sFileName, 'r')
    lZoneLines = ZoneFile.readlines()
    sInsertDomain = """INSERT IGNORE INTO domains (domain, server, keyname) VALUES (%s,%s,%s)""" 
    sSQL_Select_key = "SELECT COUNT(*) from tsig where name = %s"
    try:
        cursor.execute(sSQL_Select_key, (lZoneLines[0],) )
        result = cursor.fetchone()
    except Exception as e:
        print("Error retrieving TSIG key names: %s" % e)
        return
    if result == None:
        print("The key name (first line of file) does not match any key name presently in the WebStor database. Exiting.")
        exit(1) 
    sKey = lZoneLines[0].rstrip()
    if (not is_valid_ipv4(lZoneLines[1])):
        print("The DNS Server name (second line of file) is not a valid IP address. Exiting.")
        exit(1) 
    sServer = lZoneLines[1].rstrip()
    try:
        for sZone in lZoneLines[2:]:
            if is_valid_hostname(sZone.rstrip()):
                cursor.execute(sInsertDomain, (sZone.rstrip(),sServer,sKey) ) 
        mysqlconn.commit()
    except Exception as e:
        print("Error importing domains: %s" % e)
        return
    print("Successfully imported domains.")
    show_config("brief")
    return


def delete_domain(sDomainToRemove):
    print("Attempting to delete domain: %s" % sDomainToRemove)
    sql_delete_domain = """DELETE FROM domains WHERE domain = %s""" 
    try:
        cursor.execute(sql_delete_domain, (sDomainToRemove,) )
        mysqlconn.commit()
    except Exception as e:
        print("Error deleting domain: %s" % e)
        return
    print("Successfully deleted domain.")
    show_config("brief")
    return


def clear_domains():
    print("Attempting to clear domains.")
    try:
        cursor.execute("DROP TABLE IF EXISTS domains")
        cursor.execute("CREATE TABLE IF NOT EXISTS domains (domain VARCHAR(80), server VARCHAR(80), keyname VARCHAR(80), " \
                       "PRIMARY KEY (domain))")
    except Exception as e:
        print("Error clearing domains: %s" % e)
        return
    print("Successfully cleared domains.")
    show_config("brief")
    return


def list_domains():
    print("Domains in WebStor database:\n=================================")
    sSQL_Select = "SELECT domain, server, keyname from domains"
    try:
        cursor.execute(sSQL_Select)
        lCustom = cursor.fetchall()
    except Exception as e:
        print("Error listing Wappalyzer technologies: %s" % e)
    for Domain in lCustom:
        print("%-40s Server: %-25s Key name: %s" % (Domain[0],Domain[1],Domain[2]))
    return


def is_valid_ipv4(s):
    pieces = s.split('.')
    if len(pieces) != 4: return False
    try:
        return all(0<=int(p)<256 for p in pieces)
    except ValueError:
        return False


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def main():

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    create_database()
        
    if args.ClearHttpPorts != False:
        clear_http_ports()
    if args.ClearHttpsPorts != False:
        clear_https_ports()
    if args.ClearFingerprints != False:
        clear_fingerprints()
    if args.ClearPaths != False:
        clear_paths()
    if args.ClearDomains != False:
        clear_domains()
    if args.RangeToDelete != None:
        delete_scan_range(args.RangeToDelete)
    if args.DomainToDelete != None:
        delete_domain(args.DomainToDelete)
    if args.TSIGToDelete != None:
        delete_tsig(TSIGToDelete)
    if args.HttpPortToAdd != None:
        add_http_port(args.HttpPortToAdd)
    if args.HttpsPortToAdd != None:
        add_https_port(args.HttpsPortToAdd)
    if args.Fingerprint != None:
        add_fingerprint(args.Fingerprint)
    if args.FingerprintNameToDelete != None:
        delete_fingerprint(args.FingerprintNameToDelete)
    if args.ImportFingerprintFile != None:
        import_fingerprints(args.ImportFingerprintFile)
    if args.PathToAdd != None:
        add_path(args.PathToAdd)
    if args.PathToDelete != None:
        delete_path(args.PathToDelete)
    if args.SetScanRanges != None:
        set_scan_ranges(args.SetScanRanges)
    if args.ImportScanRanges != None:
        import_scan_ranges(args.ImportScanRanges)        
    if args.DLWap != False:
        download_wappalyzer()
    if args.ListWappalyzer != False:
        list_wappalyzer()
    if args.DomainDetails != None:
        add_domain(args.DomainDetails)
    if args.ListDomains != False:
        list_domains()
    if args.ImportTSIGFile != None:
        import_tsig(args.ImportTSIGFile)
    if args.ReplacementTSIGFile != None:
        replace_tsig(args.ReplacementTSIGFile)
    if args.ImportZoneFile != None:
        import_zones_from_file(args.ImportZoneFile)
    if args.PerformZoneXfer != False:
        dns_zone_xfer(args.UseTSIGFileOnly) 
    if args.ShowConfigBrief != False:
        show_config("brief")
    if args.ShowConfigFull != False:
        show_config("full")
    if args.ForceScan != False:
        perform_masscan()
    if args.RefreshResponses != False:
        refresh_responses()
    if args.SearchPattern != None:
        search_pattern(args.SearchPattern)    
    if args.SearchFingerprint != None:
        search_fingerprint(args.SearchFingerprint)    
    if args.SearchWappalyzer != None:
        search_wappalyzer(args.SearchWappalyzer)    

start_time = time.time()


if __name__ == '__main__':
    main()
