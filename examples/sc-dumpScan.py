#!/usr/bin/env python3

""" gets the scan named on the command line and dumps all the 
attributes

Parameters:
	scanname (str): the name of the scan to dump
	verbose (bool): increase output

Returns:
	str: returns a formatted string of all the scan's attributes
"""

import os
import sys
import json
import pprint

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import pyscclient

def main():
	pp = pprint.PrettyPrinter(indent=4)
	cark = '../cark_conf.json'
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)
	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	scan = conn.get_scan(sys.argv[1])
	#pp.pprint(scan)
	print("""

id: %s
name: %s
description: %s
status: %s
ipList: %s
type: %s
policy: %s
plugin: %s
repository: %s
zone: %s
dhcpTracking: %s
classifyMitigatedAge: %s
emailOnLaunch: %s
emailOnFinish: %s
timeoutAction: %s
scanningVirtualHosts: %s
rolloverType: %s
createdTime: %s
modifiedTime: %s
ownerGroup: %s
creator: %s
owner: %s
reports: %s
assets: %s
credentials: %s
numDependents: %s
schedule: %s
policyPrefs: %s
maxScanTime: %s""" % (scan.id, scan.name, scan.description, scan.status, 
		scan.ipList, scan.type, scan.policy, scan.plugin, 
		scan.repository, scan.zone, scan.dhcpTracking, 
		scan.classifyMitigatedAge, scan.emailOnLaunch, 
		scan.emailOnFinish, scan.timeoutAction, 
		scan.scanningVirtualHosts, scan.rolloverType, scan.createdTime,
		scan.modifiedTime, scan.ownerGroup, scan.creator, scan.owner, 
		scan.reports, scan.assets, scan.credentials, 
		scan.numDependents, scan.schedule, scan.policyPrefs, 
		scan.maxScanTime))


if __name__=='__main__':
	main()
