#!/usr/bin/env python

import json
import pprint
import pyscclient
from termcolor import cprint,colored

def main():
	pp = pprint.PrettyPrinter(indent=4)
	cark = 'cark_conf.json'
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)
	#pp.pprint(cark_conf)
	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	for ass in conn.list_assets():
		#pp.pprint(ass)
		print("ID: {0}, NAME: {1}, IP COUNT: {2}".format(ass.id, ass.name, ass.ipCount))

if __name__ == '__main__':
	main()
