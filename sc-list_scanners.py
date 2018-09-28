#!/usr/bin/env python

import json
import pprint
# This is me
import pyscclient
from termcolor import cprint, colored

def main():
	pp = pprint.PrettyPrinter(indent=4)
	cark = 'cark_conf.json'
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)
	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	for s in conn.list_scanners():
		pp.pprint(s)

#		print """
"""
ID: 			%s
Name:			%s
Descr: 			%s
Status: 		%s
IP:			%s
port:			%s
useProxy:		%s
enabled:		%s
verifyHost:		%s
managePlugins:		%s
authType:		%s
cert:			%s
username:		%s
password:		%s
agentCapable:		%s
version:		%s
webVersion:		%s
numScans:		%s
numHosts:		%s
numSessions:		%s
numTCPSessions:		%s
loadAvg:		%s
uptime:			%s
pluginSet:		%s
loadedPluginSet:	%s
serverUUID:		%s
createdTime:		%s
modifiedTime:		%s
"""
"""% (s.id, s.name, s.description, \
		s.status, s.ip, s.port, \
		s.useProxy, s.enabled, s.verifyHost, s.managePlugins, \
		s.authType, s.cert, s.username, s.password, s.agentCapable, \
		s.version, s.webVersion, s.numScans, s.numHosts, s.numSessions, \
		s.numTCPSessions, s.loadAvg, s.uptime, s.pluginSet, \
		s.loadedPluginSet, s.serverUUID, s.createdTime, s.modifiedTime)

		print "zones:	",
		if len(s.zones) > 0:
			for z in s.zones:
				#pp.pprint(z)
"""
#				print """
"""
	id:			%s
	name:			%s
	description:		%s
	ipList:			%s
	createdTime:		%s
	modifiedTime:		%s
	activeScanners:		%s
	totalScanners:		%s"""
""" % (z.id, z.name, z.description, \
						z.ipList, \
						z.createdTime, z.modifiedTime, \
						z.activeScanners, z.totalScanners)
		else:
			print("		[]")
		print("nessusManagerOrgs:	{0}".format(s.nessusManagerOrgs))
"""


if __name__ == '__main__':
	main()
