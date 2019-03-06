#!/usr/bin/env python

import pprint

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
