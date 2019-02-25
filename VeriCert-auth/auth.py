import hashlib
import json
import rsa
import os
from flask import Flask, jsonify, request
from flask_mail import Mail, Message


# Instantiate our Application
app = Flask(__name__)
users = []

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = ''
mail = Mail(app)

@app.route('/confirmation/code', methods = ['POST'])
def confirmation_code():

	# get posted values including the publicKey file
	file = request.files['file']
	name = request.form['Institution']
	email = request.form['Email']
	password = request.form['Password']
	node_id = request.form['node_id']

	# compute the confirmation code from a combination of the posted data
	confirmation_code = hashlib.sha256((name + email + password + node_id).encode()).hexdigest()
	key = rsa.PublicKey.load_pkcs1(file.read()) # load the key
	cipher = rsa.encrypt((confirmation_code).encode(), key) # encrypt the confirmation code to email to user

	user = {
		'Institution': name,
		'Email': email,
		'Password': password,
		'code': confirmation_code
	}

	users.append(user)

	with open(f'{node_id}_confirmation.txt', "wb") as f:
		f.write(cipher)

	msg = Message("Confirmation code")
	msg.recipients = [email]
	msg.html = "<b>Please download the attachment and copy to your app folder</b>"

	with app.open_resource(f'{node_id}_confirmation.txt', "rb") as fp:
		msg.attach("confirmation.txt","text/plain", fp.read())

	mail.send(msg)

	return "Message sent!", 200



@app.route('/confirmation/auth', methods = ['POST'])
def confirmation_auth():
	email = request.form['Email']
	password = request.form['Password']
	code = request.form['Confirmation_code']

	for user in users:
		if user['Email'] == email and user['Password'] == password and user['code'] == code:
			response = "authenticated"
			break

	if response:
		return response, 200
	else:
		response = "Error"
		return response, 205


if __name__ == '__main__':

	app.run(host='192.168.3.119', port=5001)
