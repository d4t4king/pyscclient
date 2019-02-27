#!/usr/bin/env python

import json
import pprint
from termcolor import cprint, colored

import os, sys
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
	for s in conn.list_scans():
		#print(str(dir(s)))
		print("""Name: %s
Schedule: %s""" % (s.name, s.schedule['nextRun']))

if __name__=='__main__':
	main()
