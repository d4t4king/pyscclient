#!/usr/bin/env python

import os
import csv
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
	conn = pyscclient.Connection(cark_conf['schost'], \
		cark_conf['username'], passwd)
	total_plugins = 0
	for pf in conn.list_plugin_families():
		total_plugins += pf.count
		pp.pprint(pf)
	print("Total plugins: {0}".format(total_plugins))

if __name__ == '__main__':
	main()
