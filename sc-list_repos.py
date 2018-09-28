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
	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	for repo in conn.list_repositories():
		#pp.pprint(repo)
		print """
id:			%s
name:			%s
description:	%s
type:			%s
dataFormat:		%s
vulnCount:		%s
remoteID:		%s
remoteIP:		%s
running:		%s
downloadFormat:		%s
lastSyncTime:		%s
lastVulnUpdate:		%s
createdTime:		%s
modifiedTime:		%s
typeFields:		%s""" % (repo.id, repo.name, repo.description, \
							repo.type, repo.dataFormat, repo.vulnCount, \
							repo.remoteID, repo.remoteIP, repo.running, \
							repo.downloadFormat, repo.lastSyncTime, \
							repo.lastVulnUpdate, repo.createdTime, \
							repo.modifiedTime, repo.typeFields)


if __name__ == '__main__':
	main()
