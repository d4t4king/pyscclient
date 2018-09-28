#!/usr/bin/env python

import csv
import pprint
import pyscclient

def main():
	pp = pprint.PrettyPrinter(indent=4)
	conn = pyscclient.Connection("nessussc.sempra.com", "sv-apiuser", "##Sempra01")
	total_plugins = 0
	for pf in conn.list_plugin_families():
		total_plugins += pf.count
		pp.pprint(pf)
	print("Total plugins: {0}".format(total_plugins))

if __name__ == '__main__':
	main()
