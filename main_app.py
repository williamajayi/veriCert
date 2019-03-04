from blockchain import *
from flask_restful import Resource, Api, reqparse
from flask_jwt import JWT, jwt_required

# Instantiate our Node
app = Flask(__name__)
api = Api(app)

node_identifier = hosts.ip + str(uuid4()).replace('-', '') # generate a node identifier

# Generate the keys and convert to string
(pubkey, privkey) = rsa.newkeys(1024)

with open("keys/privateKey.pem", "wb") as private_key:
	private_key.write(privkey.save_pkcs1(format='PEM')) # write privateKey.pem to a file

with open("keys/publicKey.pem", "wb") as public_key:
	public_key.write(pubkey.save_pkcs1(format='PEM')) # write publicKey.pem to a file

# Instantiate the Blockchain
blockchain = Blockchain()

class Chain(Resource):
	def get(self):
		response = {
			'chain': blockchain.chain,
			'length': len(blockchain.chain)
		}

		return response, 200


class Transactions(Resource):
	parser = reqparse.RequestParser()
	parser.add_argument('issuing_body', type=str, required=True, help='This field is required!')
	parser.add_argument('candidate_name', type=str, required=True, help='This field is required!')
	parser.add_argument('candidate_name', type=str, required=True, help='This field is required!')
	parser.add_argument('candidate_degree', type=str, required=True, help='This field is required!')
	parser.add_argument('issue_date', required=True, help='This field is required!')
	parser.add_argument('expiry_date', required=True, help='This field is required!')
	parser.add_argument('vhash', type=str, required=True, help='This field is required!')

	def get(self):
		if blockchain.current_transactions:
			return {"current_transactions": blockchain.current_transactions}, 200
		return {"message": "There are no pending transactions to be mined"}, 200

	def post(self):
		data = Transactions.parser.parse_args()

		if blockchain.current_transactions:
			for transactions in blockchain.current_transactions:
				if transactions['vhash'] == data['vhash']:
					return {"message": "transaction already exists in queue to be mined!"}

		issuing_body = data['issuing_body']
		candidate_name = data['candidate_name']
		candidate_degree = data['candidate_degree']
		issue_date = data['issue_date']
		expiry_date = "Never" if data['expiry_date'] == "" else data['expiry_date']
		vhash = data['vhash']

		message = {
				"issuing_body": issuing_body,
				"candidate_name": candidate_name,
				"candidate_degree": candidate_degree,
				"issue_date": issue_date,
				"expiry_date": expiry_date,
				"vhash": vhash
		}

		message = json.dumps(message, sort_keys=True)
		dSignature = rsa.sign(message.encode('utf8'), privkey, 'SHA-256')

		# Create a new Transaction
		index = blockchain.new_transaction(issuing_body, candidate_name, candidate_degree, issue_date, expiry_date, vhash, node_identifier, dSignature)

		# Create a message to indicate transaction will be added to the block to be mined
		response = {'message': 'transaction will be added to Block {}'.format(index)}

		return response, 201


	def put(self):
		data = Transactions.parser.parse_args()

		if blockchain.current_transactions:
			for index, transactions in enumerate(blockchain.current_transactions): # Use the enumerate to get the index and list item
				if transactions['vhash'] == data['vhash']:
					blockchain.update_transaction(index, data)
					return {'message': 'transaction already exists in queue and will be updated!'}, 200


		issuing_body = data['issuing_body']
		candidate_name = data['candidate_name']
		candidate_degree = data['candidate_degree']
		issue_date = data['issue_date']
		expiry_date = "Never" if data['expiry_date'] == "" else data['expiry_date']
		vhash = data['vhash']

		message = {
				"issuing_body": issuing_body,
				"candidate_name": candidate_name,
				"candidate_degree": candidate_degree,
				"issue_date": issue_date,
				"expiry_date": expiry_date,
				"vhash": vhash
		}

		message = json.dumps(message, sort_keys=True)
		dSignature = rsa.sign(message.encode('utf8'), privkey, 'SHA-256')

		# Create a new Transaction
		index = blockchain.new_transaction(issuing_body, candidate_name, candidate_degree, issue_date, expiry_date, vhash, node_identifier, dSignature)

		# Create a message to indicate transaction will be added to the block to be mined
		response = {'message': 'transaction will be added to Block {}'.format(index)}

		return response, 201

	def delete(self):
		data = Transactions.parser.parse_args()

		if blockchain.current_transactions:
			for index, transactions in enumerate(blockchain.current_transactions):
				if data['vhash'] == transactions['vhash']:
					blockchain.delete_transaction(index)
		return {'message': 'transaction deleted successfully!'}, 200


class Mine(Resource):
	def get(self):
			# Get the last mined block
			last_block = blockchain.last_block

			# Get the hash of the last block and assign to previous hash
			previous_hash = blockchain.last_block['block_hash']

			# Set timestamp to now
			current_time = datetime.datetime.now()

			j = 0

			if len(blockchain.current_transactions) > 0:

				# compare every node to be mined for equality
				while j < len(blockchain.current_transactions) - 1:
					if blockchain.current_transactions[j] == blockchain.current_transactions[j+1]:
						del blockchain.current_transactions[j]
					j += 1

				i = 0
				t = 0

				while t < len(blockchain.current_transactions):
					if blockchain.current_transactions[t]['id'] == blockchain.dSignatures[t]['id']:
						dSignature = blockchain.dSignatures[t]['dSignature']

					message = {
							"issuing_body": blockchain.current_transactions[t]['issuing_body'],
							"candidate_name": blockchain.current_transactions[t]['candidate_name'],
							"candidate_degree": blockchain.current_transactions[t]['candidate_degree'],
							"issue_date": blockchain.current_transactions[t]['issue_date'],
							"expiry_date": blockchain.current_transactions[t]['expiry_date'],
							"vhash": blockchain.current_transactions[t]['vhash']
					}
					message = json.dumps(message, sort_keys=True)
					try:
						# verify the transaction using the signature and public key rsa.PublicKey.load_pkcs1(pubkey)
						rsa.verify(message.encode('utf8'), dSignature, pubkey)
					except:
						del blockchain.current_transactions[t]
					t += 1

				# check if the transaction exist in the blockchain, remove if true
				while i < len(blockchain.current_transactions):
					if blockchain.valid_transaction(blockchain.current_transactions[i]):
						del blockchain.current_transactions[i]
					i += 1

				# Mine a new block
				if len(blockchain.current_transactions) > 0:
					block = blockchain.new_block(None, current_time, previous_hash)

					# Output details of the mined block
					return {"message": "New Block Created!"}, 201
				else:
					return {"message": "One or more transactions already exists in the blockchain: No duplicate transactions allowed"}, 200
			else:
				return {'message': "There are no transactions to mine a new block: Add transactions!"}, 200


class Search(Resource):
	parser = reqparse.RequestParser()
	parser.add_argument("hash", type=str, required=True, help="Hash of certificate to verify!")

	def get(self):
		data = Search.parser.parse_args()
		blockchain.resolve_conflicts()

		# Get API key
		key = request.args.get('api_key')

		if key not in blockchain.api_key:
			return {"message": "Invalid API key!"}

		# Set counter for outer loop
		i = 1
		transaction = None

		# search through the blockchain one block at a time
		while i < len(blockchain.chain):
			# set counter for inner loop
			j = 0
			# search through each block's transactions (one transaction at a time)
			while j < len(blockchain.chain[i]['transactions']):
				# if search query(hash) found, get the transaction
				if data["hash"] == blockchain.chain[i]['transactions'][j]['vhash']:
					transaction = blockchain.chain[i]['transactions'][j], 200
					break
				j += 1
			i += 1

		# Output a message indicating hash found
		if transaction:
			response = {
				"Message": "Hash found: Certificate Verified",
				"Issuing Institution": transaction[0]["issuing_body"],
				"Candidate Name": transaction[0]["candidate_name"],
				"Candidate Degree": transaction[0]["candidate_degree"],
				"Issue Date": transaction[0]["issue_date"]
			}
			return response, 200

		return {"Message": "Hash not found - Certificate Invalid"}, 200


@app.route('/nodes/register', methods = ['GET'])
def register_nodes():
	global node_identifier

	with open("user_info.txt", "r") as user:
	    user_info = json.loads(user.read())
	    node_identifier = user_info['node_id']

	response = {
	'chain': blockchain.chain,
	'length': len(blockchain.chain),
	'node_id': node_identifier,
	}

	response = app.response_class(json.dumps(response, default=jdefault, sort_keys=False, indent=None if request.is_xhr else 2), mimetype='application/json')

	return response, 200


@app.route('/update', methods=['GET'])
def get_update():
	# Check if user's logged in
	if not session.get('loggedIn'):
		return redirect(url_for('login', loggedin='false'))

	blockchain.nodes = hosts.process_hosts(hosts.net)

	if blockchain.resolve_conflicts():
		response = {
			'message': 'Blockchain updated!',
			'node_identifier': node_identifier,
			# 'new_chain': blockchain.chain,
		}
	elif blockchain.resolve_transactions():
		# trans_update = blockchain.resolve_transactions()
		response = {
		'message': 'Transactions updated!',
		'node_identifier': node_identifier,
		# 'new_transaction' = blockchain.current_transactions
		}
	else:
		response = {
		'message': 'There are no updates at this time!',
		'node_identifier': node_identifier,
		}

	# response = app.response_class(json.dumps(response, default=jdefault, sort_keys=False, indent=None if request.is_xhr else 2), mimetype='application/json')

	return render_template("messages.html", response = response)


@app.route('/nodes', methods = ['GET'])
def nodes():
	# Check if user's logged in
	if not session.get('loggedIn'):
		return redirect(url_for('login', loggedin='false'))

	node_info = []
	blockchain.nodes = hosts.process_hosts(hosts.net)


	if len(blockchain.nodes) > 0:
		for node in blockchain.nodes:

			try:
				response = requests.get(f'http://{node}:5000/nodes/register')
			except:
				if node:
					continue
				else:
					pass

			if response.status_code == 200:
				node_id = response.json()['node_id']
				node_info.append([node,node_id])

		if len(node_info) != 0:
			return render_template('nodes.html', node_info = node_info, length = len(node_info))
		else:
			return render_template('nodes.html', node_info = "", length = len(node_info))
	else:
		return render_template('nodes.html', node_info = "", length = len(node_info))



if __name__ == '__main__':
	# Set the secret key to some random bytes. Keep this really secret!
	app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
	from argparse import ArgumentParser

	# Endpoint creation
	api.add_resource(Chain, '/chain')
	api.add_resource(Transactions, '/transactions')
	api.add_resource(Mine, "/mine")
	api.add_resource(Search, "/search")

	parser = ArgumentParser()
	parser.add_argument('-p', '--port', default=80, type=int, help='port to listen on')
	args = parser.parse_args()
	port = args.port

	app.run(port=port, use_reloader=False, debug=True, threaded=True)
