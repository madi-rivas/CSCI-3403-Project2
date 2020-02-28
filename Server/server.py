"""
	server.py - host an SSL server that checks passwords

	CSCI 3403
	Authors: Matt Niemiec and Abigail Fernandes
	Number of lines of code in solution: 140
		(Feel free to use more or less, this
		is provided as a sanity check)

	Put your team members' names: Madison Rivas, Nathan Howard, Tyler Milligan



"""

import socket
import hashlib
from Crypto.Cipher import AES
import base64
from Crypto.PublicKey import RSA

host = "localhost"
port = 10001

# import server's public key
pub_key_string = open("../pub_key.pem","r").read()
pub_key = RSA.importKey(pub_key_string)

# import server's private key
priv_key_string = open("priv_key.pem","r").read()
priv_key = RSA.importKey(priv_key_string)


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
	return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
	# TODO: Implement this function
	decrypted_key = priv_key.decrypt(session_key)
	return decrypted_key


# Write a function that decrypts a message using the session key
def decrypt_message(message, session_key):
	# TODO: Implement this function
	nonce = 16 * '\x00' 
	cypher = AES.new(session_key, AES.MODE_CBC, nonce)
	decrypted_message = cypher.decrypt(message)
	decrypted_message = str(decrypted_message, 'utf-8')
	return decrypted_message


# Encrypt a message using the session key
def encrypt_message(message, session_key):
	# TODO: Implement this function -- done
	nonce = 16 * '\x00' 
	cypher = AES.new(session_key, AES.MODE_CBC, nonce)
	encrypted_message = cypher.encrypt(message)
	return encrypted_message


# Receive 1024 bytes from the client
def receive_message(connection):
	return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
	if not data:
		print("Can't send empty string")
		return
	if type(data) != bytes:
		data = data.encode()
	connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
	try:
		reader = open("passfile.txt", 'r')
		for line in reader.read().split('\n'):
			line = line.split("\t")
			if line[0] == user:
				# TODO: Generate the hashed password -- done
				salt = line[1]
				hashed_password = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()
				return hashed_password == line[2]
		reader.close()
	except FileNotFoundError:
		return False
	return False


def main():
	# Set up network connection listener
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = (host, port)
	print('starting up on {} port {}'.format(*server_address))
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(server_address)
	sock.listen(1)

	try:
		while True:
			# Wait for a connection
			print('waiting for a connection')
			connection, client_address = sock.accept()
			try:
				print('connection from', client_address)

				# Receive encrypted key from client
				encrypted_key = receive_message(connection)

				# Send okay back to client
				send_message(connection, "okay")

				# Decrypt key from client
				plaintext_key = decrypt_key(encrypted_key)

				# Receive encrypted message from client
				ciphertext_message = receive_message(connection)

				# TODO: Decrypt message from client -- done
				decrypted_message = decrypt_message(ciphertext_message, plaintext_key)

				# TODO: Split response from user into the username and password

				# TODO: Encrypt response to client

				# Send encrypted response
				send_message(connection, ciphertext_response)
			finally:
				# Clean up the connection
				connection.close()
	finally:
		sock.close()


if __name__ in "__main__":
	main()
