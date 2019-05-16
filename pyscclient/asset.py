#!/usr/bin/env python

import pprint

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
