#!/usr/bin/python3

import json
import pprint
import netaddr
import argparse
import pyscclient

def handle_arguments():
	parser = argparse.ArgumentParser(description="Check scan status of IP.")
	parser.add_argument('--carkconf', '-c', dest='carkconf', \
		help="Full path to the CyberARK config file.")
	parser.add_argument('--ip', '-i', dest='ipaddr', \
		help="IP address to lookup.")
	args = parser.parse_args()
	return args

def main():
	pp = pprint.PrettyPrinter(indent=4)
	args = handle_arguments()
	cark = args.carkconf
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)
	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	# check the number of organizations
	print("Checking {0} organization(s) on this SC console.".format(len(conn.organizations())))
	# loop through the list of organizations and check the restrictedIPs
	for org in conn.list_orgs():
		pp.pprint(org.restrictedIPs)
	# list any active scans
	# check the ipList to see if the ip in question is a member
	pass

if __name__=='__main__':
	main()
