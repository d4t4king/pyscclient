#!/usr/bin/env python

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
