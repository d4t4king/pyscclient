#!/usr/bin/env python

import csv
import time
import pprint
import pyscclient

def main():
	pp = pprint.PrettyPrinter(indent=4)
	conn = pyscclient.Connection("nessussc.sempra.com", "sv-apiuser", "##Sempra01")
	pname_by_date = {}
	pobj_by_date = {}
	for plg in conn.get_plugins_since(2592000):
		pname_by_date[plg.pluginPubDate] = plg.name
		pobj_by_date[plg.pluginPubDate] = plg
		#print("{0}	{1}".format(time.strftime("%x %X", time.localtime(float(plg.pluginPubDate))), plg.name))
		
	with open('/tmp/plugin-timeline.csv', 'wb') as csvfile:
		writer = csv.writer(csvfile, dialect='excel')
		# header
		writer.writerow(['vulnPubDate','pluginPubDate','pluginModDate','pluginName'])
		for p in sorted(pname_by_date):
			print("{0}	{1}	{2}	{3}".format(time.strftime("%x %X", time.localtime(float(pobj_by_date[p].vulnPubDate))),\
				time.strftime("%x %X", time.localtime(float(p))), \
				time.strftime("%x %X", time.localtime(float(pobj_by_date[p].pluginModDate))), \
				pname_by_date[p]))
			writer.writerow([time.strftime("%x %X", time.localtime(float(pobj_by_date[p].vulnPubDate))), \
				time.strftime("%x %X", time.localtime(float(p))), \
				time.strftime("%x %X", time.localtime(float(pobj_by_date[p].pluginModDate))), \
				pname_by_date[p]])


if __name__ == '__main__':
	main()

