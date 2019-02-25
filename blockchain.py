import hashlib
import json
import datetime
import threading
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import hosts
import rsa
import os

import requests
from flask import Flask, jsonify, session, app, abort, request, render_template, redirect, url_for, Response, make_response


class Blockchain:

	def __init__(self):
		self.current_transactions = ["Genesis block"]
		self.chain = []
		self.dSignatures = []
		self.nodes = hosts.process_hosts(hosts.net) #Initialize nodes from the hosts module
		self.genesis_creation = datetime.datetime.today() #Set a genesis block creation time e.g datetime.datetime(2018,3,30,12)

		# Create the genesis block
		self.new_block(index = 0, timestamp = self.genesis_creation, previous_hash ='0')

	def new_transaction(self, iBody, cName, cDegree, iDate, eDate, vHash, sAddress, dSignature, publicKey):
		self.dSignatures.append(dSignature)

		self.current_transactions.append({
		'issuing_body': iBody,
		'candidate_name': cName,
		'candidate_degree': cDegree,
		'issue_date': iDate,
		'expiry_date': eDate,
		'vhash': vHash,
		'senderAddress': sAddress,
		'dSignature': dSignature,
		'publicKey': publicKey,
		})

		return self.last_block['index'] + 1

	def new_block(self, index, timestamp, previous_hash=None):
		block = {
		'index': 0 if index == 0 else self.last_block['index'] + 1,
		'timestamp': timestamp.strftime('%d-%m-%Y %H:%M:%S'),
		'transactions': self.current_transactions,
		'previous_hash': previous_hash or self.hash(self.chain[-1]),
		}

		block_hash = self.hash(block)

		block['block_hash'] = block_hash

		# Reset the current list of transactions
		self.current_transactions = []

		self.chain.append(block)
		return block

	@property
	def last_block(self):
		return self.chain[-1]

	@staticmethod
	def hash(block):

		def jdefault(o):
			if type(o) is bytes:
				return str(o)
			return o.__dict__

		# We make sure that the dictionary is ordered or we'll have inconsistent hashes
		block_string = json.dumps(block, sort_keys=True, default=jdefault).encode()
		return hashlib.sha256(block_string).hexdigest()


	def valid_chain(self, chain):
		"""
		Determine if a given blockchain is valid
		:param chain: <list> A blockchain
		:return: <bool> True if valid, False if not
		"""

		last_block = chain[0]
		curr_index = 1

		while curr_index < len(chain):
			block = chain[curr_index]
			print(f'{last_block}')
			print(f'{block}')
			print("\n-----------\n")
			# Check that the hash of the block is correct
			if block['previous_hash'] != last_block['block_hash']:
				return False

			# Check that the Proof of Work is correct
			# if not self.valid_proof(last_block['proof'], block['proof']):
			#     return False

			last_block = block
			curr_index += 1

		return True

	def valid_transaction(self, trans):
		blockchain_size = len(self.chain)
		i = 1

		while i < blockchain_size:
			j = 0
			while j < len(self.chain[i]['transactions']):
				if self.chain[i]['transactions'][j] == trans:
					return True
					break
				j += 1
			i += 1

		return False

	def resolve_transactions(self):
		neighbours = self.nodes


		new_transactions = self.current_transactions

		for n in neighbours:
			try:
				r = requests.get(f'http://{n}:5000/transactions/current')
			except:
				if n:
					continue
				else:
					return False

			if r.status_code == 205:
				# length = r.json()['length']
				trans = r.json()['current_transaction']
				# dsign = r.json()['digital_signature']

				if new_transactions != trans: # check if the neighbours list of transactions is different
					for i in trans: # if it is different loop through and compare transactions
						if i not in new_transactions:
							new_transactions.append(i)



		if new_transactions:
			self.current_transactions = new_transactions
			# self.dSignatures = dsign
			return True

		return False


	def resolve_conflicts(self):
		"""
		This is our Consensus Algorithm, it resolves conflicts
		by replacing our chain with the longest one in the network.
		:return: <bool> True if our chain was replaced, False if not
		"""
		new_chain = None

		# We're only looking for chains longer than ours
		max_length = len(self.chain)

		# Grab and verify the chains from all the nodes in our network
		for node in self.nodes:
			try:
				response = requests.get(f'http://{node}:5000/nodes/register')
			except:
				if node:
					continue
				else:
					return False

			if response.status_code == 200:
				length = response.json()['length']
				chain = response.json()['chain']

				# Check if the length is longer and the chain is valid
				if length > max_length and self.valid_chain(chain):
					max_length = length
					new_chain = chain
			else:
				del node

		# Replace our chain if we discovered a new, valid chain longer than ours
		if new_chain:
			self.chain = new_chain
			return True

		return False


	def register_node(self, address):
		"""
		Add a new node to the list of nodes
		:param address: <str> Address of node. Eg. 'http://192.168.0.5:5000'
		:return: None
		"""

		parsed_url = urlparse(address)
		if parsed_url.netloc:
			self.nodes.add(parsed_url.netloc)
		elif parsed_url.path:
			self.nodes.add(parsed_url.path)
		else:
			raise ValueError('Invalid URL')
