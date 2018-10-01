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
	for user in conn.list_users():
		#pp.pprint(user)
		print("id: {0}, {1}, {2} ({3}) {4}".format(user.id, user.lastname, \
			user.firstname, user.username, user.orgID))
	#orgs = conn.organizations()
	for org in conn.list_orgs():
		cprint("ORG: {0}".format(org.id), "cyan", attrs=["bold"])
		for user in conn.list_users(orgID=org.id):
			print("id: {0}, {1}, {2} ({3}) {4}".format(user.id, user.lastname, \
				user.firstname, user.username, user.orgID))

if __name__ == '__main__':
	main()
