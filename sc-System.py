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
	sys = conn.getSystem()
	#pp.pprint(sys)
	print("""
	Version: %s
	Build ID: %s
	Banner: %s
	Release ID: %s
	UUID: %s
	Logo: %s
	ServerAuth: %s
	ServerClassification: %s
	SessionTimeout: %s
	LicenseStatus: %s
	Mode: %s
	ACAS: %s
	FreshInstall: %s
	HeaderText: %s
	PasswordComplexity: %s
	""" % (sys.version, sys.buildID, sys.banner, sys.releaseID, \
		sys.uuid, sys.logo, sys.serverAuth, sys.serverClassification, \
		sys.sessionTimeout, sys.licenseStatus, sys.mode, sys.ACAS, \
		sys.freshInstall, sys.headerText, sys.PasswordComplexity))

if __name__== '__main__':
	main()
