#!/usr/bin/env python

import json
from termcolor import cprint
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import pyscclient

def main():
	cark = '../cark_conf.json'
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)
	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	cprint("Basic status output:", "green", attrs=["bold"])
	conn.getStatus()
	cprint("Verbose status output:", "green", attrs=["bold"])
	conn.getStatus(True)

if __name__== '__main__':
	main()
