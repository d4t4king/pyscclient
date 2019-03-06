#!/usr/bin/env python

import json
import time
import pprint
import datetime
import subprocess
from termcolor import colored, cprint
from securitycenter import SecurityCenter5

from .scan import Scan
from .scanzone import Zone
from .asset import Asset
from .scanner import Scanner
from .repository import Repository
from .organization import Organization

class Connection(object):
	"""A class to handle the basic connection to the SecurityCenter
	console API.  This is the foundation for most object manipulation.

	Instance Methods:
		getStatus (response): returns the output of the status query
			to the API
		list_scanners (yield, list): returns a terable list of
			pyscclient.Scanner objects attached to the Tenable.SC
			console.
		scanners (list): returns a static list of pyscclient.Scanner
			objects attached to the Tenable.SC console.
		list_zones (yield, list): returns an iterable list of scan zones
		list_orgs (yield, list): returns an iterable list of
			organizations
		list_repositories (yield, list): returns and iterable list of
			repositories
		plugins (list): returns a list of all plugins
		list_plugins (yield, list): returns an iterable list of all
			plugins
		get_plugins_since (yield, list): returns an iterable list of
			all plugins published since date
		list_plugin_families (yield, list): returns an iterable list
			of all plugin families
		list_scans (yield, list): returns an iterable list of all scans
		list_assets (yield, list): returns an iterable list of all assets
	"""

	def __init__(self, host, user, passwd):
		""" Initializer

		Parameters:
			host (str): hostname or IP address for the Tenable.SC
				console
			user (str): username used to connect to the console
				For most purposes, this should be a user in the
				Security Manager role.  There are some operations,
				however, that do require administrative privileges,
				like manipulating scans.
			passwd (str): the user's password
		"""

		self.host = host
		self.user = user
		self.passwd = passwd
		self.sc = SecurityCenter5(self.host)
		self.sc.login(self.user, self.passwd)

	def getStatus(self, verbose=False):
		""" Gets a collection of status information, including license.

		Parameters:
			verbose (boolean): optional, increases the level of output
		Returns:
			list: prints a list of strings
		"""

		response = self.sc.get('status')
		rh = response.json()['response']
		if verbose:
			print("""
jobd:					%s
licenseStatus:				%s
PluginSubscriptionStatus:		%s
LCEPluginSubscriptionStatus:		%s
PassivePluginSubscriptionStatus:	%s """ % (rh['jobd'], \
						rh['licenseStatus'], rh['PluginSubscriptionStatus'], \
						rh['LCEPluginSubscriptionStatus'], \
						rh['PassivePluginSubscriptionStatus']))
			print("pluginUpdates:")
			for k in rh['pluginUpdates']:
				print("	{0}: ".format(k))
				for e in rh['pluginUpdates'][k]:
					print("		{0}: {1}".format(e, rh['pluginUpdates'][k][e]))
			print("feedUpdates:")
			for k in rh['feedUpdates']:
				print("	{0}: {1}".format(k, rh['feedUpdates'][k]))
			print("""
activeIPs:				%s
licensedIPs				%s """ % (rh['activeIPs'], rh['licensedIPs']))
		else:
			print("""
jobd:		%s
licenseStatus:	%s
activeIPs:	%s
licensedIPs:	%s """ % (rh['jobd'], rh['licenseStatus'], \
				rh['activeIPs'], rh['licensedIPs']))


	def list_scanners(self):
		""" Gets a list of scanners

		Returns:
			generator: returns an iterable list of scanners
		"""

		pp = pprint.PrettyPrinter(indent=4)
		fields = ["id"]
		response = self.sc.get('scanner', params={"fields": ",".join(fields)})
		for _id in response.json()['response']:
			scn = Scanner.load(self.sc, _id['id'])
			yield scn

	def scanners(self):
		""" Gets a list of scanners

		Returns:
			list: returns a (complete) list of scanners
		"""

		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('scanner', params={'fields': ",".join(fields)})
		scanners = []
		for _id in response.json()['response']:
			scn = Scanner.load(self.sc, _id['id'])
			scanners.append(scn)
		return scanners

	def list_zones(self):
		""" Gets a list of scan zones

		Returns:
			list: returns an iterable list of scan zones
		"""

		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('zone', params={'fields': ",".join(fields)})
		for _id in response.json()['response']:
			zn = Zone.load(self.sc, _id['id'])
			yield zn

	def list_orgs(self):
		""" Gets a list of organizations

		Returns:
			generator: returns an iterable list of organizations
		"""

		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('organization', params={"fields": ",".join(fields)})
		#pp.pprint(response.json())
		for org in response.json()['response']:
			org_obj = Organization.load(self.sc, org['id'].decode('utf-8'))
			yield org_obj

	def list_repositories(self):
		""" Gets a list of repositories

		Returns:
			generator: returns an iterable list of repositories
		"""

		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('repository', params={"fields": ",".join(fields)})
		for repo in response.json()['response']:
			repo_obj = Repository.load(self.sc, repo['id'])
			yield repo_obj

	def plugins(self):
		""" Gets all plugins

		Returns:
			list: returns a list of all plugins.
		"""

		pp = pprint.PrettyPrinter(indent=4)
		plugins = []
		fields = ['id']
		response = self.sc.get('plugin', params={'fields': ",".join(fields), 'endOffset':'110000'})
		for p in response.json()['response']:
			plug = Plugin.load(self.sc, p['id'])
			plugins.append(plug)
		return plugins

	def list_plugins(self):
		""" Gets all plugins

		Returns:
			generator: returns a list of all plugins
		"""

		pp = pprint.PrettyPrinter(indent=4)
		plugins = []
		fields = ['id']
		response = self.sc.get('plugin', params={'fields': ",".join(fields), 'endOffset':'110000'})
		for p in response.json()['response']:
			plug = Plugin.load(self.sc, p['id'])
			yield plug

	def get_plugins_since(self, start_date):
		""" Gets plugins published since date

		Returns:
			generator: returns a list of plugins since the specified
				start_date in seconds.  Defaults to the last 90 days:
			(60 (seconds) * 60 (minutes) * 24 (hours) * 90 (days))
		"""

		plugins = []
		response = self.sc.get('plugin', params={'fields':['id'], \
			'endOffset':'100', 'since':start_date})
		for p in response.json()['response']:
			plug = Plugin.load(self.sc, p['id'])
			yield plug

	def list_plugin_families(self):
		""" Gets all plugin families

		Returns:
			generator: returns the list ofi plugin families
		"""

		fields = ['id']
		response = self.sc.get('pluginFamily', params={'fields':",".join(fields)})
		for pf in response.json()['response']:
			pf_obj = PluginFamily.load(self.sc, pf['id'])
			yield pf_obj

	def list_scans(self):
		""" Gets all scans

		Returns:
			generator: returns a list of all scans
		"""

		pp = pprint.PrettyPrinter(indent=4)
		scans = list()
		fields = ['id']
		response = self.sc.get('scan', params={'fields': ",".join(fields)})
		for s in response.json()['response']['manageable']:
			scan = Scan.load(self.sc, s['id'])
			yield scan

	def get_scan(self, scanname):
		""" Gets the scan with name __scanname__

		Parameters:
			scanname (str): name of the scan to retrieve
		Returns:
			pyscclient.Scan: returns the scan object with the supplied
				name
		"""

		pp = pprint.PrettyPrinter(indent=4)
		for s in self.list_scans():
			if scanname in s.name:
				return s

	def list_assets(self):
		""" Gets the list of assets

		Returns:
			generator: returns an iterable list of assets
		"""

		pp = pprint.PrettyPrinter(indent=4)
		assets = list()
		fields = ['id']
		response = self.sc.get('asset', params={'fields': ",".join(fields)})
		for ma in response.json()['response']['usable']:
			ass = Asset.load(self.sc, ma['id'])
			yield ass
