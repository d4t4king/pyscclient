#!/usr/bin/env python

import csv
import json
import time
import pprint
import pyscclient
import subprocess
from termcolor import cprint,colored

def main():
	pp = pprint.PrettyPrinter(indent=4)
	cark = 'cark_conf.json'
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)

	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	with open('/tmp/plugin-dump.csv', 'wb') as csvfile:
		writer = csv.writer(csvfile, dialect='excel')
		writer.writerow(['id','name','description','family','type','version','riskFactor', \
					'solution','synopsis','checkType','exploitAvailable','baseScore', \
					'temporalSCore','stigSeverity','pluginPubDate','pluginModDate', \
					'vulnPubDate','modifiedTime'])
		for p in conn.list_plugins():
			# default 90 days
			pp.pprint(p)
			try:
				writer.writerow([str(p.id),p.name,p.type,p.version,p.riskFactor, \
					p.solution,p.synopsis,p.checkType,p.exploitAvailable,str(p.baseScore), \
					str(p.temporalScore),p.stigSeverity, \
					str(time.strftime("%x %X", time.localtime(p.pluginPubDate))), \
					str(time.strftime("%x %X", time.localtime(p.pluginModDate))), \
					str(time.strftime("%x %X", time.localtime(p.vulnPubDate))), \
					str(time.strftime("%x %X", time.localtime(p.modifiedTime)))])
			except:
				cprint("There was an error", "red")


if __name__ == '__main__':
	main()
