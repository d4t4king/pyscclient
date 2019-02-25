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
	try:
		conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	except pyscclient.APIError as apierr:
		if 'Invalid login credentials' in str(apierr):
			print("Invalid login credentials.")
			exit(1)
	for s in conn.list_zones():
		pp.pprint(s)

if __name__ == '__main__':
	main()
