#!/usr/bin/env pythong

import json

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
