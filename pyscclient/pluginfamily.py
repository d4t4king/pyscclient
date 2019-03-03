#!/usr/bin/env python

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
