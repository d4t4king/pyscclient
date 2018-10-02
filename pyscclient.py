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

import json
import time
import pprint
import datetime
import subprocess
#import securitycenter
from termcolor import colored, cprint
from securitycenter import SecurityCenter5
#import securitycenter

__name__ = "pyscclient"
__version__ = '0.1'

class APIError(Exception):
	def __init__(self, code, msg):
		self.code = code
		self.message = msg

	def __str__(self):
		return repr('[%s]: %s' % (self.code, self.message))

class Connection(object):
	def __init__(self, host, user, passwd):
		self.host = host
		self.user = user
		self.passwd = passwd
		self.sc = SecurityCenter5(self.host)
		self.sc.login(self.user, self.passwd)

	def getStatus(self, verbose=False):
		"""
			Gets a collection of status information, including license.
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

	def getSystem(self):
		sys = System.load(self.sc)
		return sys
		
	def list_scanners(self):
		"""
			Iterable list of scanners.
			This is where my lack of python experience comes in....
			maybe an array is just as iterable as this generator?
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ["id"]
		response = self.sc.get('scanner', params={"fields": ",".join(fields)})
		for _id in response.json()['response']:
			scn = Scanner.load(self.sc, _id['id'])
			yield scn

	def scanners(self):
		"""
			This is mainly a test to see about iterating lists
			over generators.
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
		"""
			Iterable list of scan zones
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('zone', params={'fields': ",".join(fields)})
		for _id in response.json()['response']:
			zn = Zone.load(self.sc, _id['id'])
			yield zn

	def list_orgs(self, **kwargs):
		"""
			Iterable list of Organizations.
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('organization', params={"fields": ",".join(fields)})
		pp.pprint(response.json())
		for org in response.json()['response']:
			org_obj = Organization.load(self.sc, org['id'])
			yield org_obj

	def organizations(self):
		"""
			Returns the array of organizations.
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		resp = self.sc.get('organization', params={"fields": ",".join(fields)})
		orgs = list()
		for org in resp.json()['response']:
			org_obj = Organization.load(self.sc, org['id'])
			orgs.append(org_obj)
		return orgs

	def list_repositories(self):
		"""
			Iterable list of Repository's.
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('repository', params={"fields": ",".join(fields)})
		for repo in response.json()['response']:
			repo_obj = Repository.load(self.sc, repo['id'])
			yield repo_obj

	def plugins(self):
		"""
			Returns a list of all plugins.
			This *should* be iterable.  (Note above comments.)
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
		"""
			Returns a list of all plugins.
			This *should* be iterable.  (Note above comments.)
		"""
		pp = pprint.PrettyPrinter(indent=4)
		plugins = []
		fields = ['id']
		response = self.sc.get('plugin', params={'fields': ",".join(fields), 'endOffset':'110000'})
		for p in response.json()['response']:
			plug = Plugin.load(self.sc, p['id'])
			yield plug

	def get_plugins_since(self, start_date):
		"""
			Returns a list of plugins since the
			specified start_date in seconds.
			Defaults to the last 90 days:
			(60 (seconds) * 60 (minutes) * 24 (hours) * 90 (days))
		"""
		plugins = []
		#params = {}
		#params['fields'] = "id"
		#params['endOffset'] = 10000
		#params['since'] = start_date
		response = self.sc.get('plugin', params={'fields':['id'], \
			'endOffset':'100', 'since':start_date})
		for p in response.json()['response']:
			plug = Plugin.load(self.sc, p['id'])
			yield plug
		#	plugins.append(plug)
		#return plugins

	def list_plugin_families(self):
		"""
			Generator object that returns the list of
			plugin families
		"""
		fields = ['id']
		response = self.sc.get('pluginFamily', params={'fields':",".join(fields)})
		for pf in response.json()['response']:
			pf_obj = PluginFamily.load(self.sc, pf['id'])
			yield pf_obj

	def list_users(self, **kwargs):
		"""
			Generator object that returns the list of users
		"""
		fields = ['id']
		resp = None
		if kwargs:
			print("DEBUG: **kwargs is not None. ({0})".format(kwargs))
			if 'orgID' in kwargs:
				print("DEBUG: Found orgID key in **kwargs.")
				resp = self.sc.get('user', params={"fields":",".join(fields), "orgID": kwargs['orgID']})
			else:
				resp = self.sc.get('user', params={'fields':",".join(fields)})
		else:
			resp = self.sc.get('user', params={'fields':",".join(fields)})
		print(resp.url)
		for u in resp.json()['response']:
			user = User.load(self.sc, u['id'])
			yield user

	def list_manageable_assets(self):
		"""
			Generator object that returns the list of manageable assets

			Note:  The API differentiates between "manageable" assets and
			"usable" assets.  I don't quite know what the distinction is, so
			the intent here is to create methods for both and all.
		"""
		fields = ['id']
		resp = self.sc.get('asset', params={"fields":",".join(fields)})
		for ass in resp.json()['response']['manageable']:
			asset = Asset.load(self.sc, ass['id'])
			yield asset

	def list_usable_assets(self):
		"""
			Generator object that returns the list of usable assets.
		"""
		fields = ['id']
		resp = self.sc.get('asset', params={"fields":",".join(fields)})
		for ass in resp.json()['response']['usable']:
			asset = Asset.load(self.sc, ass['id'])
			yield asset

	def list_assets(self):
		"""
			Generator object that returns the list of all assets.
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		resp = self.sc.get('asset', params={"fields":",".join(fields)})
		#pp.pprint(resp.json()['response']['manageable'])
		assets = list()
		for ass in resp.json()['response']['usable']:
			asset = Asset.load(self.sc, ass['id'])
			assets.append(asset)
		for ass in resp.json()['response']['manageable']:
			asset = Asset.load(self.sc, ass['id'])
			if asset not in assets:
				assets.append(asset)
		for a in assets:
			yield a

class BasicAPIObject(object):
	def __init__(self):
		self.id = 0
		self.name = ''
		self.description = ''

class Alert(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.status = ''
		self.owner = ''
		self.ownerGroup = ''
		self.triggerName = ''
		self.triggerOperator = ''
		self.triggerValue = ''
		self.modifiedTime = 0
		self.createdTime = 0
		self.lastTriggered = 0
		self.lastEvaluated = 0
		self.executeOnEveryTrigger = False
		self.didTriggerLastEvaluation = False
		self.schedule = None
		self.action = ''
		self.query = ''
		self.canUse = False
		self.canManage = False

	@staticmethod
	def load(sc, _id):
		# get the data from the REST API
		resp = sc.get('alert', params={'id':['id']})
		rb = resp.json()['response']
		# instantiate the empty object
		alert = Alert()
		alert.id = _id
		alert.__dict__.update(rb)
		return alert

class Asset(BasicAPIObject):
	# represents an Asset in object form
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.status = ''
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
		pp = pprint.PrettyPrinter(indent=4)
		# load the Asset from the console in object form
		resp = sc.get('asset', params={'id':_id})
		#print("URL: {0}".format(resp.url))
		rb = resp.json()['response']
		#pp.pprint(rb)
		asset = Asset()
		asset.__dict__.update(rb)
		return asset

class AuditFile(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.type = ''
		self.status = ''
		self.groups = list()
		self.creator = ''
		self.version = ''
		self.context = ''
		self.filename = ''
		self.originalFilesname = ''
		self.modifiedTime = 0
		self.createTime = 0
		self.lastRefreshedTime = 0
		self.canUse = False
		self.canManage = False
		self.auditFileTemplate = ''
		self.typeFields = ''
		self.ownerGroup = ''
		self.targetGroup = ''

	@staticmethod
	def load(_id, *args):
		print('NYI')
		pass

class Credential(BasicAPIObject):
	def __init__(self, **kwargs):
		super(BasicAPIObject, self).__init__()
		self.type = ''
		self.creator = ''
		self.target = ''
		self.groups = list()
		self.typeFields = None
		self.tags = list()
		self.createdTime = 0
		self.modifiedTime = 0
		self.canUse = False
		self.canManage = False
		self.owner = ''
		self.ownerGroup = ''
		self.targetGroup = ''

	@staticmethod
	def load(_id, *args):
		print('NYI')
		pass

class CurrentUser(BasicAPIObject):
	def __init__(self, _id):
		super(BasicAPIObject, self).__init__()
		self.type = ''
		self.creator = ''
		self.target = ''
		self.groups = ''
		self.typeFields = None
		self.tags = list()
		self.createdTime = 0
		self.modifiedTime = 0
		self.canUse = False
		self.canManage = False
		self.owner = ''
		self.ownerGroup = ''
		self.targetGroup = ''

	@staticmethod
	def load(self, _id):
		print('NYI')
		pass

class Group(BasicAPIObject):
	def __init__(self, _id):
		super(BasicAPIObject, self).__init__()
		self.createdTime = 0
		self.modifiedTime = 0
		self.lces = list()								# list of LCEs
		self.repositories = list()						# list of Repositories
		self.definingAssets = list()					# list of Assets
		self.userCount = 0
		self.users = list()
		self.assets = list()
		self.policies = list()
		self.queries = list()
		self.credentials = list()
		self.dashboardTabs = list()
		self.arcs = list()
		self.auditFiles = list()

	@staticmethod
	def load(self, _id):
		print('FYI')
		pass

class IPInfo(object):
	def __init__(self, _ip):
		self.ip = _ip
		self.repositoryID = 0
		self.repositories = list()
		self.repository = ''
		self.score = 0
		self.total = 0
		self.severityInfo = ''
		self.severityLow = ''
		self.severityMedium = ''
		self.severityHigh = ''
		self.severityCritical = ''
		self.macAddress = ''
		self.policyName = ''
		self.pluginSet = ''
		self.netbiosName = ''
		self.dnsName = ''
		self.osCPE = ''
		self.biosGUID = ''
		self.tpmID = ''
		self.mcafeeGUID = ''
		self.lastAuthRun = 0
		self.lastUnauthRun = 0
		self.severityAll = 0
		self.os = ''
		self.hasPassive = False
		self.hasCompliance = False
		self.lastScan = 0
		self.links = list()

	def load(self, _ip):
		print('NYI')
		pass

class Organization(BasicAPIObject):
	# represents the Organization in SC
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.email = ''
		self.address = ''
		self.city = ''
		self.state = ''
		self.country = ''
		self.phone = ''
		self.fax = ''
		self.ipInfoLinks = list()
		self.zoneSelection = ''
		self.restrictedIPs = ''
		self.vulnScoreLow = 0
		self.vulnScoreMedium = 0
		self.vulnScoreHigh = 0
		self.vulnScoreCritical = 0
		self.createdTime = 0
		self.modifiedTime = 0
		self.userCount = 0
		self.lces = list()					# an array of LCE objects
		self.repositories = list()			# as array of Respository objects
		self.zones = list()					# an array of Zone objects
		self.nessusManagers = list()
		self.pubSites = list()
		self.ldaps = list()

	def __repr__(self):
		mystr = """
	id=%s, name=%s, description=%s, email=%s, address=%s, city=%s,
	state=%s, country=%s, phone=%s, fax=%s, ipInfoLinks=%s,
	zoneSelection=%s, restrictedIPs=%s, vulnScoreLow=%s
	vulnScoreMedium=%s, vulnScoreHigh=%s, vulnScoreCritical=%s
	createdTime=%s, modifiedTime=%s, userCount=%s, lces=%s,
	repositories=%s, zones=%s, nessusManagers=%s, pubSites=%s,
	ldaps=%s""" % (self.id, self.name, self.description, \
	self.email, self.address, self.city, self.state, self.country, \
	self.phone, self.fax, self.ipInfoLinks, self.zoneSelection, \
	self.restrictedIPs, self.vulnScoreLow, self.vulnScoreMedium, \
	self.vulnScoreHigh, self.vulnScoreCritical, self.createdTime, \
	self.modifiedTime, self.userCount, self.lces, self.repositories, \
	self.zones, self.nessusManagers, self.pubSites, self.ldaps)
		return mystr

	@staticmethod
	def load(sc, org_id):
		# loads the Organization object with the specified ID from the console
		resp = sc.get('organization', params={'id': org_id})
		rb = resp.json()['response']
		org = Organization()
		org.__dict__.update(rb)
		return org

class Plugin(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
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
		rb = response.json()['response']
		p = Plugin()
		p.__dict__.update(rb)
		return p

class PluginFamily(BasicAPIObject):
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

class Query(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.creator = ''
		self.owner = ''
		self.ownerGroup = ''
		self.targetGroup = ''
		self.tool = ''
		self.type = ''
		self.tags = list()
		self.context = ''
		self.browseColumns = list()
		self.browseSortColumns = ''
		self.browseSortDirection = ''
		self.createdTime = 0
		self.modifiedTime = 0
		self.status = ''
		self.filters = list()
		self.canManage = False
		self.canUse = False
		self.groups = list()

	@staticmethod
	def load(self, _id):
		print('NYI')
		pass

class ReportTypes(object):
	def __init__(self, name, type, enabled, attributeSets=list()):
		self.name = name
		self.type = type
		self.enabled = enabled
		self.sttributeSets = attributeSets

class Repository(BasicAPIObject):
	# represents a Repository in object form
	TYPE_ALL = 'All'
	TYPE_LOCAL = 'Local'
	TYPE_REMOTE = 'Remote'
	TYPE_OFFLINE = 'Offline'

	def __init__(self):
		super(BasicAPIObject, self).__init__()
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
		self.organizations = list()

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
		return repo

class Role(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.creator = None
		self.createdTime = 0
		self.modifiedTime = 0
		self.permManageApp = False
		self.permManageGroups = False
		self.permManageRoles = False
		self.perlManageImages = False
		self.permManageGroupRelationships = False
		self.permManageBlackoutWindows = False
		self.permManageAttributeSets = False
		self.permCreateTickets = False
		self.permCreateAlerts = False
		self.permCreateAuditFiles = False
		self.permCreateLDAPAssets = False
		self.permCreatePolicies = False
		self.permPurgeTickets = False
		self.permPurgeScanResults = False
		self.permPurgeReportResults = False
		self.permScan = False
		self.permAgentsScan = False
		self.permShareObjects = False
		self.permUpdateFeeds = False
		self.permUploadNessusResults = False
		self.permViewOrgLogs = False
		self.permManageAcceptRiskRules = False
		self.permManageRecastRiskRules = False
		self.organizationCounts = None

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		resp = sc.get('role', params={'id': _id})
		rb = resp.json()['response']
		role = Role()
		role.__dict__.update(rb)
		return role

class Scan(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
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
		resp = sc.get('scan', params={'id': _id})
		rb = resp.json()['response']
		scan = Scan()
		scan.__dict__.update(rb)
		return scan

class ScanPolicy(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.status = 0
		self.policyTemplate = None
		self.policyProfileName = ''
		self.creator = ''
		self.tags = list()
		self.createdTime = 0
		self.modifiedTime = 0
		self.context = ''
		self.generateXCCDFResults = False
		self.auditFiles = list()
		self.preferences = ''
		self.targetGroup = ''
		self.groups = list()
		self.families = list()
		self.usable = False
		self.manageable = False

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		resp = sc.get('policy', params={'id': _id})
		rb = resp.json()['response']
		sp = ScanPolicy()
		sp.__dict__.update(rb)
		return sp

class ScanResults(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.status = 0
		self.initiator = ''
		self.owner = ''
		self.ownerGroup = ''
		self.repository = None
		self.scan = None
		self.job = ''
		self.details = ''
		self.importStatus = ''
		self.importStart = 0
		self.importFinish = 0
		self.importDuration = 0
		self.downloadAvailable = False
		self.downloadFormat = ''
		self.dataFormat = ''
		self.resultType = ''
		self.resultSource = ''
		self.running = False
		self.errorDetails = ''
		self.importErrorDetails = ''
		self.totalIPs = 0
		self.scannedIPs = 0
		self.startTime = 0
		self.finishTime = 0
		self.scanDuration = 0
		self.completedIPs = 0
		self.completedChecks = 0
		self.totalChecks = 0
		self.progress = None

class Scanner(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
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
		pp = pprint.PrettyPrinter(indent=4)
		resp = sc.get('scanner', params={"id":scanner_id})
		rb = resp.json()['response']
		scn = Scanner()
		scn.__dict__.update(rb)
		return scn

	def save(self, sc):
		# save the Scanner object to the console
		# this can be a new scanner object, or a modified, existing one
		pass

class System(object):

	class Disagnostics(object):
		def __init__(self, sc):
			resp = sc.get('diagnostics')
			rb = resp.json()['response']
			diag = Diagnostics()
			diag.__dict__.update(rb)

		@staticmethod
		def generate(sc):
			opts = dict()
			params = dict()
			opts['options'] = "all"
			params['task'] = 'disgnosticsFile'
			resp = sc.post('diagnostics', params)
			return int(resp.json()['error_code'])

	def __init__(self):
		self.reportTypes = list()
		self.version = 0.0
		self.buildID = ''
		self.banner = ''
		self.releaseID = ''
		self.uuid = ''
		self.logo = ''
		self.serverAuth = ''
		self.serverClassification = ''
		self.sessionTimeout = 0
		self.licenseStatus = ''
		self.mode = ''
		self.ACAS = False
		self.freshInstall = False
		self.headerText = ''
		self.PasswordComplexity = False
		self.timezones = list()
		self.scLogs = dict()
		self.diagnostics = Diagnostics()

	@staticmethod
	def load(sc):
		"""
			Loads the system details
		"""
		system = System()
		resp = sc.get('system')
		rb = resp.json()['response']
		tzs = list()
		rts = list()
		for tz in rb['timezones']:
			tzobj = Timezone(tz['name'], tz['gmtOffset'])
			tzs.append(tzobj)
		system.timezones = tzs
		for rt in rb['reportTypes']:
			rtobj = ReportType(rt['name'], rt['type'],rt['enabled'],rt['attributeSets'])
			rts.append(rtobj)
		system.reportTypes = rts
		system.version = rb['version']
		system.buildID = rb['buildID']
		system.banner = rb['banner']
		system.releaseID = rb['releaseID']
		system.uuid = rb['uuid']
		system.logo = rb['logo']
		system.serverAuth = rb['serverAuth']
		system.serverClassification = rb['serverClassification']
		system.sessionTimeout = int(rb['sessionTimeout'])
		system.licenseStatus = rb['licenseStatus']
		system.mode = rb['mode']
		system.ACAS = rb['ACAS']
		if rb['freshInstall'] == 'no':
			system.freshInstall = False
		elif rb['freshInstall'] == 'yes':
			system.freshInstall = True
		else:
			raise("Unknown fresh install state: {0}.  Expected 'yes' or 'no'.".format(rb['freshInstall']))
		system.headerText = rb['headerText']
		system.PasswordComplexity = rb['PasswordComplexity']
		system.scLogs = rb['scLogs']
		return system

class TimeZone(object):
	def __init__(self, name, offset):
		self.name = name
		self.gmtOffset = float(offset)

class User(object):
	def __init__(self):
		self.id = 0
		self.username = ''
		self.firstname = ''
		self.lastname = ''
		self.status = ''
		self.role = None						# Role?
		self.title = ''
		self.email = ''
		self.address = ''
		self.city = ''
		self.state = ''
		self.country = ''
		self.phone = ''
		self.fax = ''
		self.createdTime = ''
		self.modifiedTime = ''
		self.lastLogin = 0
		self.lastLoginIP = ''
		self.mustChangePassword = False
		self.locked = False
		self.failedLogins = 0
		self.authType = ''
		self.fingerprint = ''
		self.password = ''
		self.description = ''
		self.canUse = False
		self.canManage = False
		self.managedUsersGroups = list()
		self.managedObjectsGroups = list()
		self.preferences = list()
		self.ldaps = ''
		self.ldapUsername = ''
		self.responsibleAsset = None
		self.orgID = 0

	#def __repr__(self):
	#	my_str = """
	#id: %s, username: %s, firstname: %s, lastname: %s, status: %s, role: %s,
	#title: %s, email: %s, address: %s, city: %s, state: %s, country:
	#	""" % (self.id, self.username, self.firstname, self.lastname, self.status, \
	#	self.role, self.title, self.email, self.address, self.city, self.state, \
	#	self.country)
	#	return my_str

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		resp = sc.get('user', params={'id': _id})
		rb = resp.json()['response']
		user = User()
		user.__dict__.update(rb)
		return user

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

class Zone(BasicAPIObject):
	# represents the scan Zone in SC in object form
	def __init__(self):
		super(BasicAPIObject, self).__init__()
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
		rb = response.json()['response']
		zn = Zone()
		return zn

	def save(self, sc):
		# adds a new scan zone to the console
		pass
