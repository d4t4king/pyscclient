#!/usr/bin/env python

#######################################################################
#	pyscclient
#
#	This module is a wrapper for SteveMcGrath's pySecurityCenter.
#	It is intended to abstract the API one layer further, objectifying
#	most of the objects available in the API
#
#######################################################################
#	THIS SCRIPT USES TABS
#######################################################################
#	INDEX
########################################################################

import json
import time
import pprint
import datetime
import subprocess
from termcolor import colored, cprint
from securitycenter import SecurityCenter5

__name__ = "pyscclient"
__version__ = '0.1'

class APIError(Exception):
	"""A class to handle API Errors

	Attributes:
		code (int): an integer code number
		message (str): the string message for the error
	"""

	def __init__(self, code, msg):
		"""Initializer

		Parameters:
			code (int): number reporesenting the error code
			message (str): a message describing the error
		"""

		self.code = code
		self.message = msg

	def __str__(self):
		return repr('[%s]: %s' % (self.code, self.message))

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


class Scanner(object):
	def __init__(self, _id, _name, descr, **args):
		self.id = _id
		self.name = _name
		self.description = descr
		self.status = ''
		# handle extra args in here somewhere
		# instantiate some default values
		self.ip = ''
		self.port = ''
		self.useProxy = False
		self.enabled = True
		self.verifyHost = False
		self.managePlugins = True
		self.authType = ''
		self.cert = ''
		self.username = ''
		self.password = ''
		self.agentCapable = False
		self.version = 0
		self.webVersion = 0
		self.admin = ''
		self.msp = ''
		self.numScans = 0
		self.numTCPSessions = 0
		self.loadAvg = 0
		self.uptime = 0
		self.pluginSet = ''
		self.loadedPluginSet = ''
		self.serverUUID = ''
		self.createdTime = ''
		self.modifiedTime = ''
		self.zones = []					# a list of Zones (scan zones) associated with the scanner
		self.nessusManagerOrgs = []		# not sure if this should be an array just yet.

	def __repr__(self):
		my_str = "id:%s; name:%s; status:%s; ip:%s; port:%s; \
enabled:%s; agentCapable:%s; version:%s; webVersion:%s; \
uptime:%s; loadedPluginSet:%s; createdTime:%s; zoneCount:%s;" % \
			(self.id, self.name, self.status, self.ip, self.port, \
				self.enabled, \
				self.agentCapable, self.version, self.webVersion, \
				self.uptime, self.loadedPluginSet, self.createdTime, \
				len(self.zones))
		return my_str

	@staticmethod
	def load(sc, scanner_id):
		# load the scanner info from the console
		# fields = ["id", "name", "description", "status", \
		#	"ip", "port", "useProxy", "enabled", "verifyHost", \
		#	"managePlugins", "authType", "cert", "username", \
		#	"password", "agentCapable", "version"]
		pp = pprint.PrettyPrinter(indent=4)
		resp = sc.get('scanner', params={"id":scanner_id})
		scn = Scanner(scanner_id, resp.json()['response']['name'], \
						resp.json()['response']['description'])
		scn.status = resp.json()['response']['status']
		scn.ip = resp.json()['response']['ip']
		if resp.json()['response']['port'] is not None:
			scn.port = int(resp.json()['response']['port'])
		scn.useProxy = resp.json()['response']['useProxy']
		scn.enabled = resp.json()['response']['enabled']
		scn.verifyHost = resp.json()['response']['verifyHost']
		scn.managePlugins = resp.json()['response']['managePlugins']
		scn.authType = resp.json()['response']['authType']
		scn.cert = resp.json()['response']['cert']
		scn.username = resp.json()['response']['username']
		scn.password = resp.json()['response']['password']
		scn.agentCapable = resp.json()['response']['agentCapable']
		scn.version = resp.json()['response']['version']
		scn.webVersion = resp.json()['response']['webVersion']
		scn.admin = resp.json()['response']['admin']
		scn.msp = resp.json()['response']['msp']
		if resp.json()['response']['numScans'] is not None:
			scn.numScans = int(resp.json()['response']['numScans'])
		if resp.json()['response']['numHosts'] is not None:
			scn.numHosts = int(resp.json()['response']['numHosts'])
		if resp.json()['response']['numSessions'] is not None:
			scn.numSessions = int(resp.json()['response']['numSessions'])
		if resp.json()['response']['numTCPSessions'] is not None:
			scn.numTCPSessions = int(resp.json()['response']['numTCPSessions'])
		if resp.json()['response']['loadAvg'] is not None:
			scn.loadAvg = float(resp.json()['response']['loadAvg'])
		if resp.json()['response']['uptime'] is not None:
			scn.uptime = int(resp.json()['response']['uptime'])
		scn.pluginSet = resp.json()['response']['pluginSet']
		scn.loadedPluginSet = resp.json()['response']['loadedPluginSet']
		scn.serverUUID = resp.json()['response']['serverUUID']
		if resp.json()['response']['createdTime'] is not None:
			scn.createdTime = int(resp.json()['response']['createdTime'])
		if resp.json()['response']['modifiedTime'] is not None:
			scn.modifiedTime = int(resp.json()['response']['modifiedTime'])
		for ele in resp.json()['response']['zones']:
			z = Zone.load(sc, ele['id'])
			scn.zones.append(z)
		#scn.zones = resp.json()['response']['zones']
		scn.nessusManagerOrgs = resp.json()['response']['nessusManagerOrgs']
		#print colored("=", "red") * 65
		#print("ID: {0}, Name: {1}, Desc: {2}, Status: {3}".format( \
		#	colored(scn.id, "green"), colored(scn.name, "green"), \
		#	colored(scn.description, "green"), colored(scn.status, "green")))
		#print colored("=", "red") * 65
		return scn

	def save(self, sc):
		# save the Scanner object to the console
		# this can be a new scanner object, or a modified, existing one
		pass

class Zone(object):
	# represents the scan Zone in SC in object form
	def __init__(self, _id, _name, description):
		self.id = _id
		self.name = _name
		self.description = description
		self.ipList = []
		self.createdTime = 0
		self.modifiedTime = 0
		self.organizations = []			# a list of Organization objects
		self.activeScanners = 0
		self.totalScanners = 0
		self.scanners = []				# a list of Scanner objects

	def __repr__(self):
		my_str = "id:%s; name:%s; ipList:[%s]; createdTime:%s; \
modifiedTime:%s; orgCount:%s; activeScanners:%s; \
totalScanners:%s;" % (self.id, self.name, self.ipList, \
						self.createdTime, self.modifiedTime, \
						len(self.organizations), self.activeScanners, \
						self.totalScanners)
		return my_str

	@staticmethod
	def load(sc, zone_id):
		# loads an existing Zone from the console
		response = sc.get('zone', params={'id': zone_id})
		zn = Zone(zone_id, response.json()['response']['name'], \
						response.json()['response']['description'])
		zn.ipList = response.json()['response']['ipList']
		if response.json()['response']['createdTime'] is not None:
			zn.createdTime = int(response.json()['response']['createdTime'])
		if response.json()['response']['modifiedTime'] is not None:
			zn.modifiedTime = int(response.json()['response']['modifiedTime'])
		zn.organizations = response.json()['response']['organizations']
		if response.json()['response']['activeScanners'] is not None:
			zn.activeScanners = int(response.json()['response']['activeScanners'])
		if response.json()['response']['totalScanners'] is not None:
			zn.totalScanners = int(response.json()['response']['totalScanners'])
		zn.scanners = response.json()['response']['scanners']
		return zn

	def save(self, sc):
		# adds a new scan zone to the console
		pass

class Organization(object):
	# represents the Organization in SC
	def __init__(self, _id, _name, descr):
		self.id = _id
		self.name = _name
		self.description = descr
		self.email = ''
		self.address = ''
		self.city = ''
		self.state = ''
		self.country = ''
		self.phone = ''
		self.fax = ''
		self.ipInfoLinks = []
		self.zoneSelection = ''
		self.restrictedIPs = ''
		self.vulnScoreLow = 0
		self.vulnScoreMedium = 0
		self.vulnScoreHigh = 0
		self.vulnScoreCritical = 0
		self.createdTime = 0
		self.modifiedTime = 0
		self.userCount = 0
		self.lces = []					# an array of LCE objects
		self.repositories = []			# as array of Respository objects
		self.zones = []					# an array of Zone objects
		self.nessusManagers = []
		self.pubSites = []
		self.ldaps = []

	def to_json(self):
		# need to replace the lists of objects with JSON
		jrepos = list()
		for r in self.repositories:
			jrepos.append(r.__dict__)
		self.repositories = jrepos
		return json.dumps(self.__dict__)

	@staticmethod
	def update(sc, org_id, **kwargs):
		pp = pprint.PrettyPrinter(indent=4)
		#pp.pprint(kwargs)
		#print("============")
		#pp.pprint(json.dumps(kwargs))
		#for k,v in kwargs.items():
		#	print("k'{0}' is type {1}".format(k, type(v)))
		resp = sc.sc.patch('organization/{0}'.format(org_id), \
			params=kwargs)
		return resp.json()['error_code']

	@staticmethod
	def load(sc, org_id):
		#print("DEBUG: In Organization.load()")
		# loads the Organization object with the specified ID from the console
		resp = sc.get('organization', params={'id': org_id})
		org = Organization(org_id, resp.json()['response']['name'], \
							resp.json()['response']['description'])
		org.email = resp.json()['response']['email']
		org.address = resp.json()['response']['address']
		org.city = resp.json()['response']['city']
		org.state = resp.json()['response']['state']
		org.country = resp.json()['response']['country']
		org.phone = resp.json()['response']['phone']
		org.fax = resp.json()['response']['fax']
		for ele in resp.json()['response']['ipInfoLinks']:
			org.ipInforLinks.append(ele)
		org.zoneSelection = resp.json()['response']['zoneSelection']
		org.restrictedIPs = resp.json()['response']['restrictedIPs']
		if resp.json()['response']['vulnScoreLow'] is not None:
			org.vulnScoreLow = int(resp.json()['response']['vulnScoreLow'])
		if resp.json()['response']['vulnScoreMedium'] is not None:
			org.vulnScoreMedium = int(resp.json()['response']['vulnScoreMedium'])
		if resp.json()['response']['vulnScoreHigh'] is not None:
			org.vulnScoreHigh = int(resp.json()['response']['vulnScoreHigh'])
		if resp.json()['response']['vulnScoreCritical'] is not None:
			org.vulnScoreCritical = int(resp.json()['response']['vulnScoreCritical'])
		if resp.json()['response']['createdTime'] is not None:
			org.createdTime = int(resp.json()['response']['createdTime'])
		if resp.json()['response']['modifiedTime'] is not None:
			org.modifiedTime = int(resp.json()['response']['modifiedTime'])
		if resp.json()['response']['userCount'] is not None:
			org.userCount = int(resp.json()['response']['userCount'])
		for ele in resp.json()['response']['lces']:
			lce = LCE.load(sc, ele['id'])
			org.lces.append(lce)
		for ele in resp.json()['response']['repositories']:
			repo = Repository.load(sc, ele['id'])
			org.repositories.append(repo)
		for ele in resp.json()['response']['zones']:
			z = Zone.load(sc, ele['id'])
			org.zones.append(z)
		return org

class Asset(object):
	# represents an Asset in object form
	def __init__(self, _name, descr, _status):
		self.name = _name
		self.description = descr
		self.status = _status
		self.creator = ''
		self.owner = ''
		self.ownerGroup = ''
		self.targetGroup = ''
		self.groups = 0					# This might be an array.
		self.template = ''
		self.typeFields = ''			# This might be an array or hash.
		self.type = ''
		self.tags = ''
		self.context = ''
		self.createdTime = 0			# This might could be a DateTime type object.
		self.modifiedTime = 0			# This might could be a DateTime type object.
		self.respositories = []			# This is likely an array.
		self.ipCount = 0
		self.assetDataFields = []		# This is likely an array or hash.
		self.viewableIPs = []			# Probably an array; may cause slow processing, i.e. a lot of data.
		# should probably set filter parameters
		# usable, managable, excludeAllDefined, excludeWatchlists


	@staticmethod
	def load(sc, _id):
		# load the Asset from the console in object form
		pp = pprint.PrettyPrinter(indent=4)
		r = sc.get('asset', params={"id":_id})
		#pp.pprint(r.json()['response'])
		a = Asset(r.json()['response']['name'], \
			r.json()['response']['description'], \
			r.json()['response']['status'])
		a.creator = r.json()['response']['creator']
		a.owner = r.json()['response']['owner']
		a.ownerGroup = r.json()['response']['ownerGroup']
		a.targetGroup = r.json()['response']['targetGroup']
		if 'groups' in r.json()['response'].keys():
			a.groups = r.json()['response']['groups']
		a.template = r.json()['response']['template']
		a.typeFields = r.json()['response']['typeFields']
		a.type = r.json()['response']['type']
		a.tags = r.json()['response']['tags']
		a.context = r.json()['response']['context']
		a.createdTime = r.json()['response']['createdTime']
		a.modifiedTime = r.json()['response']['modifiedTime']
		# loop through the repo list and create repo objects for
		# each item
		a.repositories = r.json()['response']['repositories']
		a.ipCount = r.json()['response']['ipCount']
		a.assetDataFields = r.json()['response']['assetDataFields']
		if 'viewableIPs' in r.json()['response'].keys():
			a.viewableIPs = r.json()['response']['viewableIPs']
		return a

class Repository(object):
	# represents a Repository in object form
	TYPE_ALL = 'All'
	TYPE_LOCAL = 'Local'
	TYPE_REMOTE = 'Remote'
	TYPE_OFFLINE = 'Offline'

	def __init__(self, _id, _name, descr):
		self.id = _id
		self.name = _name
		self.description = descr
		self.type = ''
		self.dataFormat = ''
		self.vulnCount = 0
		self.remoteID = 0
		self.remoteIP = ''
		self.running = False
		self.downloadFormat = ''
		self.lastSyncTime = 0
		self.lastVulnUpdate = 0
		self.createdTime = 0
		self.modifiedTime = 0
		self.transfer = ''
		self.typeFields = ''
		self.remoteSchedule = ''
		self.organizations = []
		self.groupAssign = None

	def to_json(self):
		return json.dumps(self.__dict__)

	@staticmethod
	def load(sc, repo_id):
		pp = pprint.PrettyPrinter(indent=4)
		response = sc.get('repository', params={'id': repo_id})
		#pp.pprint(response.json()['response'])
		repo = Repository(repo_id, response.json()['response']['name'], \
					response.json()['response']['description'])
		repo.type = response.json()['response']['type']
		repo.dataFormat = response.json()['response']['dataFormat']
		if response.json()['response']['vulnCount'] is not None:
			repo.vulnCount = int(response.json()['response']['vulnCount'])
		repo.remoteID = response.json()['response']['remoteID']
		repo.remoteIP = response.json()['response']['remoteIP']
		repo.running = response.json()['response']['running']
		repo.downloadFormat = response.json()['response']['downloadFormat']
		repo.lastSynceTime = int(response.json()['response']['lastSyncTime'])
		repo.lastVulnUpdate = int(response.json()['response']['lastVulnUpdate'])
		repo.createdTime = int(response.json()['response']['createdTime'])
		repo.modifiedTime = int(response.json()['response']['modifiedTime'])
		# in the documentation not returned (unless possibly specified)
		#repo.transfer = response.json()['response']['transfer']
		repo.typeFields = response.json()['response']['typeFields']
		# in the documentation not returned (unless possibly specified)
		#repo.remoteSchedule = response.json()['response']['remoteSchedule']
		# seems to cause some crazy recursion.  removeing to verify
		#for o in response.json()['response']['organizations']:
		#	org = Organization.load(sc, o['id'])
		#	repo.organizations.append(o)
		if 'groupAssign' in response.json()['response']:
			repo.groupAssign = response.json()['response']['groupAssign']
		else:
			repo.groupAssign = ''
		return repo

class PluginFamily(object):
	def __init__(self, _id, _name):
		self.id = _id
		self.name = _name
		self.type = ''
		self.count = 0

	def __repr__(self):
		return "id:{0}; name:{1}; type:{2}; count:{3};".format( \
				self.id, self.name, self.type, self.count)

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		response = sc.get('pluginFamily', params={'id': _id})
		pf = PluginFamily(_id, response.json()['response']['name'])
		pf.type = response.json()['response']['type']
		pf.count = int(response.json()['response']['count'])
		return pf

	def to_string(self):
		return "id: {0} name: {1} type: {2} count: {3}".format( \
				self.id, self.name, self.type, self.count)

class Plugin(object):
	def __init__(self, _id, _name=None):
		self.id = _id
		self.name = _name
		self.description = ''
		self.family = ''			# this should be a PluginFamily object
		self.type = ''
		self.copyright = ''
		self.version = ''
		self.sourceFile = ''
		self.source = ''
		self.dependencies = ''
		self.requiredPorts = ''
		self.requiredUDPPorts = ''
		self.cpe = ''
		self.srcPort = 0
		self.dstPort = 0
		self.protocol = ''
		self.riskFactor = ''
		self.solution = ''
		self.seeAlso = ''
		self.synopsis = ''
		self.checkType = ''
		self.exploitEase = ''
		self.exploitAvailable = ''
		self.exploitFrameworks = ''
		self.cvssVector = ''
		self.cvssVectorBF = ''
		self.baseScore = 0
		self.temporalScore = 0
		self.stigSeverity = 0
		self.pluginPubDate = 0
		self.pluginModDate = 0
		self.patchPubDate = 0
		self.patchModDate = 0
		self.vulnPubDate = 0
		self.modifiedTime = 0
		self.md5 = ''
		self.xrefs = []

	def __repr__(self):
		my_str = "id:%s; name:%s; familyName:%s; type:%s; \
riskFactor:%s; baseScore:%s; pluginPubDate:%s; \
pluginModDate:%s; vulnPubDate:%s; modifiedTime:%s;" % (
			self.id, self.name, self.family.name, self.type, \
			self.riskFactor, self.baseScore, \
			time.strftime("%x %X", time.localtime(float(self.pluginPubDate))), \
			time.strftime("%x %X", time.localtime(float(self.pluginModDate))), \
			time.strftime("%x %X", time.localtime(float(self.vulnPubDate))), \
			time.strftime("%x %X", time.localtime(float(self.modifiedTime))))
		return my_str

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		response = sc.get('plugin', params={'id': _id})
		p = Plugin(_id, response.json()['response']['name'])
		p.description = response.json()['response']['description']
		pfam = PluginFamily.load(sc, response.json()['response']['family']['id'])
		p.family = pfam
		p.type = response.json()['response']['type']
		p.copyright = response.json()['response']['copyright']
		p.version = response.json()['response']['version']
		p.sourceFile = response.json()['response']['sourceFile']
		p.source = response.json()['response']['source']
		p.dependencies = response.json()['response']['dependencies']
		p.requiredPorts = response.json()['response']['requiredPorts']
		p.requiredUDPPorts = response.json()['response']['requiredUDPPorts']
		p.cpe = response.json()['response']['cpe']
		if response.json()['response']['srcPort'] is not None:
			p.srcPort = int(response.json()['response']['srcPort'])
		if response.json()['response']['dstPort'] is not None:
			p.dstPort = int(response.json()['response']['dstPort'])
		p.protocol = response.json()['response']['protocol']
		p.riskFactor = response.json()['response']['riskFactor']
		p.solution = response.json()['response']['solution']
		p.seeAlso = response.json()['response']['seeAlso']
		p.synopsis = response.json()['response']['synopsis']
		p.checkType = response.json()['response']['checkType']
		p.exploitEase = response.json()['response']['exploitEase']
		p.exploitAvailable = response.json()['response']['exploitAvailable']
		p.exploitFrameworks = response.json()['response']['exploitFrameworks']
		p.cvssVector = response.json()['response']['cvssVector']
		p.cvssVectorBF = response.json()['response']['cvssVectorBF']
		if response.json()['response']['baseScore'] is not None:
			p.baseScore = float(response.json()['response']['baseScore'])
		if response.json()['response']['temporalScore'] is not None:
			p.temporalScore = float(response.json()['response']['temporalScore'])
		p.stigSeverity = response.json()['response']['stigSeverity']
		if response.json()['response']['pluginPubDate'] is not None:
			p.pluginPubDate = int(response.json()['response']['pluginPubDate'])
		if response.json()['response']['pluginModDate'] is not None:
			p.pluginModDate = int(response.json()['response']['pluginModDate'])
		if response.json()['response']['patchPubDate'] is not None:
			p.patchPubDate = int(response.json()['response']['patchPubDate'])
		if response.json()['response']['patchModDate'] is not None:
			p.patchModDate = int(response.json()['response']['patchModDate'])
		if response.json()['response']['vulnPubDate'] is not None:
			p.vulnPubDate = int(response.json()['response']['vulnPubDate'])
		if response.json()['response']['modifiedTime'] is not None:
			p.modifiedTime = int(response.json()['response']['modifiedTime'])
		p.md5 = response.json()['response']['md5']
		for x in response.json()['response']['xrefs']:
			p.xrefs.append(x)
		return p

class Scan(object):
	def __init__(self, _id):
		self.id = _id
		self.name = ''
		self.description = ''
		self.status = ''
		self.ipList = list()
		self.type = ''
		self.policy = ''		# policy is listed twice in the API docs.  Why?  Typo?
		self.plugin = ''
		self.repository = ''
		self.zone = ''
		self.dhcpTracking = ''
		self.classifyMitigatedAge = ''
		self.emailOnLaunch = False
		self.emailOnFinish = False
		self.timeoutAction = ''
		self.scanningVirtualHosts = ''
		self.rolloverType = ''
		self.createdTime = 0
		self.modifiedTime = 0
		self.ownerGroup = ''
		self.creator = ''
		self.owner = ''
		self.reports = ''
		self.assets = list()		# should this be a list()?  A dict()?  An Object()?
		self.credentials = list()
		self.numDependents = 0
		self.schedule = None
		self.policyPrefs = ''
		self.maxScanTime = 0

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		response = sc.get('scan', params={'id': _id})
		s = Scan(response.json()['response']['id'])
		s.name = response.json()['response']['name']
		s.description = response.json()['response']['description']
		s.status = response.json()['response']['status']
		s.ipList = response.json()['response']['ipList']
		s.type = response.json()['response']['type']
		s.policy = response.json()['response']['policy']
		s.plugin = response.json()['response']['plugin']
		s.repository = response.json()['response']['repository']
		s.zone = response.json()['response']['zone']
		s.dhcpTracking = response.json()['response']['dhcpTracking']
		s.classifyMitigatedAge = response.json()['response']['classifyMitigatedAge']
		s.emailOnLaunch = response.json()['response']['emailOnLaunch']
		s.emailOnFinish = response.json()['response']['emailOnFinish']
		s.timeoutAction = response.json()['response']['timeoutAction']
		s.scanningVirtualHosts = response.json()['response']['scanningVirtualHosts']
		s.rolloverType = response.json()['response']['rolloverType']
		s.createdTime = int(response.json()['response']['createdTime'])
		s.modifiedTime = int(response.json()['response']['modifiedTime'])
		s.ownerGroup = response.json()['response']['ownerGroup']
		s.creator = response.json()['response']['creator']
		s.owner = response.json()['response']['owner']
		s.reports = response.json()['response']['reports']
		for ar in response.json()['response']['assets']:
			a = Asset.load(sc, ar['id'])
			s.assets.append(a)
		#s.assets = response.json()['response']['assets']
		s.credentials = response.json()['response']['credentials']
		s.numDependents = int(response.json()['response']['numDependents'])
		s.schedule = response.json()['response']['schedule']
		s.policyPrefs = response.json()['response']['policyPrefs']
		s.maxScanTime = response.json()['response']['maxScanTime']
		return s

class Utils(object):
	def __init__(self):
		pass

	@staticmethod
	def get_cark_creds(config):
		p = subprocess.Popen(["ssh", "root@{0}".format(config['aimproxy']), \
"/opt/CARKaim/sdk/clipasswordsdk", "GetPassword", "-p", \
"AppDescs.AppID={0}".format(config['appid']), "-p", \
"\"Query=safe={0};Folder={1};Object={2}\"".format(
config['safe'], config['folder'], config['objectname']), "-o", \
"Password"], stdout=subprocess.PIPE)
		tup_pass = p.communicate()
		p = tup_pass[0].decode('ascii')
		p = p.strip()
		return p
