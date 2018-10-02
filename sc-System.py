#!/usr/bin/python3

import json
import pprint
import pyscclient
from termcolor import cprint

def main():
	pp = pprint.PrettyPrinter(indent=4)
	cark = 'cark_conf.json'
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)
	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	sys = pyscclient.System.load(conn)
	pp.pprint(sys)

if __name__== '__main__':
	main()
