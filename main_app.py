from blockchain import *

# Instantiate our Node
app = Flask(__name__)

node_identifier = ""

pubkey = ""
privkey = ""

def jdefault(o):
	if type(o) is bytes:
		return str(o)
	return o.__dict__

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/')
def index():
	return main()

@app.route('/chain', methods=['GET'])
def full_chain():
	# Check if user's logged in
	# if not session.get('loggedIn'):
	# 	return redirect(url_for('login', loggedin='false'))

	# output the full blockchain
	# response = {
	# 'chain': blockchain.chain,
	# 'length': len(blockchain.chain)
	# }

	length = len(blockchain.chain)
	chain = blockchain.chain


	# response = app.response_class(json.dumps(response, default=jdefault, sort_keys=False, indent=None if request.is_xhr else 2), mimetype='application/json')
    # return response, 200

	return render_template("chain.html", blockchain = chain, length = length, node_identifier = node_identifier) , 200



@app.route('/new_transaction', methods=['POST'])
def new_transaction():
	# Check if user's logged in
	if not session.get('loggedIn'):
		return redirect(url_for('login', loggedin='false'))

	# Check if the number of current transactions is not up to 10, create transaction
	# if true
	if len(blockchain.current_transactions) < 10:

		# values = request.get_json()
		# values = json.dumps(values, sort_keys=False)

		issuing_body = request.form['issuing_body']
		candidate_name = request.form['candidate_name']
		candidate_degree = request.form['candidate_degree']
		issue_date = request.form['issue_date']
		expiry_date = "Never" if request.form['expiry_date'] == "" else request.form['expiry_date']
		vhash = request.form['vhash']

		message = {
				"issuing_body": issuing_body,
				"candidate_name": candidate_name,
				"candidate_degree": candidate_degree,
				"issue_date": issue_date,
				"expiry_date": expiry_date,
				"vhash": vhash
		}

		privkey1 = session.get('privkey')
		privkey = rsa.PrivateKey.load_pkcs1(privkey1)

		pubkey1 = session.get('pubkey')
		pubkey = rsa.PublicKey.load_pkcs1(pubkey1)

		node_address = session.get('node_address')

		message = json.dumps(message, sort_keys=True)
		dSignature = rsa.sign(message.encode('utf8'), privkey, 'SHA-256')


		# Check that the required fields are in the POST'ed data
		# required = ['issuing body', 'candidate name', 'candidate degree', 'issue date', 'expiry date', 'vhash']
		# if not all(k in values for k in required):
		# 	return 'Missing values', 400

		# Create a new Transaction
		index = blockchain.new_transaction(issuing_body, candidate_name, candidate_degree, issue_date, expiry_date, vhash, node_address, dSignature, pubkey1)

		# Create a message to indicate transaction will be added to the block to be mined
		response = {'message': f'Transaction will be added to Block {index}'}


		# check if neighbours exist
		# if blockchain.nodes != 0:
		# 	chain_thread = threading.Timer(3, blockchain.resolve_conflicts())  # timer is set to 3 seconds
		# 	chain_thread.start()
		#
		# 	transaction_thread = threading.Timer(3, blockchain.resolve_transactions())
		# 	transaction_thread.start()

		return render_template("messages.html", response = response)

	else:
		# Mine a new block if the number of transactions is
		return mine()


@app.route('/mine_block')
def mine_block():
	# Check if user's logged in
	if not session.get('loggedIn'):
		return redirect(url_for('login', loggedin='false'))

	if request.args.get('index'):
		x = int(request.args.get('index'))
		del blockchain.current_transactions[x]

	if len(blockchain.current_transactions) > 0:
		i = 0
		while i < len(blockchain.current_transactions):
			if blockchain.valid_transaction(blockchain.current_transactions[i]):
				del blockchain.current_transactions[i]
				break
			i += 1

		# Output details of the mined block
		length = len(blockchain.current_transactions)
		current_transactions = blockchain.current_transactions

		return render_template("mine.html", length = length, current_transactions = current_transactions)
	else:
		length = len(blockchain.current_transactions)
		current_transactions = blockchain.current_transactions

		return render_template("mine.html", length = length, current_transactions = current_transactions)



@app.route('/mine', methods=['GET'])
def mine():
	# Check if user's logged in
	if not session.get('loggedIn'):
		return redirect(url_for('login', loggedin='false'))

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
			pubkey = blockchain.current_transactions[t]['publicKey']
			dSignature = blockchain.current_transactions[t]['dSignature']
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
				# verify the transaction using the signature and public key
				rsa.verify(message.encode('utf8'), dSignature, rsa.PublicKey.load_pkcs1(pubkey))
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
			response = {
			'message': "New Block Created!",
			}
		else:
			response = {
			'message': "One or more transactions already exists in the blockchain: No duplicate transactions allowed"
			}
	else:
		response = {
		'message': "There are no transactions to mine a new block: Add transactions!"
		}

	# response = app.response_class(json.dumps(response, default=jdefault, sort_keys=False, indent=None if request.is_xhr else 2), mimetype='application/json')
	return render_template("messages.html", response = response)


@app.route('/search', methods=['GET'])
def search():
	blockchain.resolve_conflicts()

	# Get the hash to verify
	q = request.args.get('q')
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
			if str(q) == blockchain.chain[i]['transactions'][j]['vhash']:
				transaction = blockchain.chain[i]['transactions'][j], 200
				break
			j += 1
		i += 1

	# Output a message indicating hash found
	if transaction:
		response = {
			"Message": "Hash found: Certificate Verified",
			# "Transaction": transaction,
		}
	else:
		response = {
			"Message": "Hash not found - Certificate Invalid"
		}

	# response = app.response_class(json.dumps(response, default=jdefault, sort_keys=False, indent=None if request.is_xhr else 2), mimetype='application/json')
	return render_template("response.html", server_response = response)


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

@app.route('/transactions/current', methods = ['GET'])
def current_transaction():
	# Check if user's logged in
	# if not session.get('loggedIn'):
	# 	return redirect(url_for('login', loggedin='false'))

	pubkey = session.get('pubkey')
	privkey = session.get('privkey')

	if len(blockchain.current_transactions) > 0:
		i = 0
		while i < len(blockchain.current_transactions):
			if blockchain.valid_transaction(blockchain.current_transactions[i]):
				del blockchain.current_transactions[i]
				break
			i += 1

		# Output details of the mined block
		response = {
		'length': len(blockchain.current_transactions),
		'current_transaction': blockchain.current_transactions,
		'address': node_identifier,
		'neighbours': blockchain.nodes
		}
		response = app.response_class(json.dumps(response, default=jdefault, indent=None if request.is_xhr else 2), mimetype='application/json')
		return response, 205
	else:
		response = {
		'message': "There are no transactions!",
		'neighbours': blockchain.nodes,
		# 'publicKey': pubkey,
		# 'privateKey': privkey,
		'address': node_identifier,
		}
		response = app.response_class(json.dumps(response, default=jdefault, indent=None if request.is_xhr else 2), mimetype='application/json')
		return response, 206


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

@app.route('/main')
def main():
	testpub = pubkey
	testpriv = privkey
	return render_template('index.html')


@app.route('/logout')
def logout():
	session['loggedIn'] = False

	return redirect(url_for('login', loggedout = "true"))


@app.route('/login')
def login():
	if session.get('loggedIn'):
		return redirect(url_for('full_chain')) # redirect to the blockchain page if already logged in

	if request.args.get('loggedin'):
		messages = "You must be logged in"
	elif request.args.get('loggedout'):
		messages = "You have been logged out!"
	elif request.args.get('error') == "invalid_login":
		messages = "Email & Password combination is incorrect, try again!"
	else:
		messages = ""

	return render_template('login.html', messages = messages)



@app.route('/process_login', methods = ['POST'])
def process_login():
	global node_identifier
	if session.get('loggedIn'):
		return redirect(url_for('full_chain')) # redirect to the blockchain page if already logged in

	_email = request.form['iEmail']
	_password = request.form['iPassword']
	_password = hashlib.sha256(_password.encode()).hexdigest()

	with open("user_info.txt", "r") as user:
	    user_info = json.loads(user.read())
	    node_id = node_identifier = user_info['node_id']

	with open('keys/privateKey.pem') as private_key:
		privatekey = rsa.PrivateKey.load_pkcs1(private_key.read())

	with open(f'{node_id}_confirmation.txt', "rb") as file:
		confirmation_code = rsa.decrypt(file.read(), privatekey) # decrypt the confirmation.txt file to get the confirmation code

	post = {
		'Email': _email,
		'Password': _password,
		'Confirmation_code': confirmation_code
	}

	url = 'http://192.168.3.119:5001/confirmation/auth'

	response = requests.post(url, data = post)

	if response.status_code == 200 and response.text == "authenticated":
		session.permanent = True
		app.permanent_session_lifetime = datetime.timedelta(minutes=5)
		session['loggedIn'] = True

		with open('keys/privateKey.pem') as private_key:
			privkey = session['privkey'] = private_key.read()

		with open('keys/publicKey.pem') as public_key:
			pubkey = session['pubkey'] = public_key.read()


		return redirect(url_for('full_chain'))
	else:
		return redirect(url_for('login', error = "invalid_login"))


@app.route('/signup')
def signup():
	if session.get('loggedIn'):
		return redirect(url_for('full_chain')) # redirect to the blockchain page if already logged in

	return render_template('signup.html')


@app.route('/new')
def new():
	if not session.get('loggedIn'):
		return redirect(url_for('full_chain')) # redirect to the blockchain page if already logged in

	return render_template('new.html')


@app.route('/process_signup', methods = ['POST'])
def process_signup():
	global node_identifier

	if session.get('loggedIn'):
		return redirect(url_for('full_chain')) # redirect to the blockchain page if already logged in

	_name = request.form['iName']
	_email = request.form['iEmail']
	_password = request.form['iPassword']
	_password = hashlib.sha256(_password.encode()).hexdigest()

	node_identifier = str(uuid4()).replace('-', '') # generate a node identifier

	data = {
		'Institution': _name,
		'Email': _email,
		'Password': _password,
		'node_id': node_identifier
	}

	with open('user_info.txt', 'w') as user_info:
		json.dump(data, user_info)

	# Generate the keys and convert to string
	(pubkey, privkey) = rsa.newkeys(1024)
	pubkey = pubkey.save_pkcs1(format='PEM')
	privkey = privkey.save_pkcs1(format='PEM')

	with open("keys/privateKey.pem", "wb") as private_key:
		private_key.write(privkey) # write to privateKey.pem file

	with open("keys/publicKey.pem", "wb") as public_key:
		public_key.write(pubkey) # write to publicKey.pem file


	url = 'http://192.168.3.119:5001/confirmation/code'
	files = {'file': open('keys/publicKey.pem', 'rb')}


	response = requests.post(url, files = files, data = data)


	if response.status_code == 200:
		server_res = ["Sign up request received!", "Please check your email for confirmation code"]
	else:
		server_res = ["Sign up request failed", ""]

	return render_template('pending_signup.html', server_res = server_res), 200




if __name__ == '__main__':
	import os
	# Set the secret key to some random bytes. Keep this really secret!
	app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
	from argparse import ArgumentParser

	parser = ArgumentParser()
	parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
	args = parser.parse_args()
	port = args.port

	app.run(host=f'{hosts.ip}', port=port, use_reloader=False, use_debugger=False, threaded=True)
