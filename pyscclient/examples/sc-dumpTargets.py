#!/usr/bin/env python

""" Gets the targets of the scans in the file list and dumps the
contents to files named for the Asset

Parameters:
	inputfile (file): a file containing the list of assets to dump
Returns:
	outputfiles (files): outputs a groups of files containing the IPs
		that comprise the Asset
"""

import os
import sys
import json
import pprint

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import pyscclient

def main():
	assets_to_dump = list()
	with open(sys.argv[1], 'r') as f:
		for line in f:
			assets_to_dump.append(line.strip("\n").strip(" "))

	pp = pprint.PrettyPrinter(indent=4)
	cark = '../cark_conf.json'
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)
 	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)

	for a in conn.list_assets():
		if a.name in assets_to_dump:
			with open("{0}.txt".format(a.name), 'w') as out:
				print("{0}".format(a.viewableIPs))
				out.write(str(a.viewableIPs))
		else:
			print("{0} not in list: {1}".format(a.name, assets_to_dump))
			

if __name__=='__main__':
	main()
