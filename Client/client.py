"""
	client.py - Connect to an SSL server

	CSCI 3403
	Authors: Matt Niemiec and Abigail Fernandes
	Number of lines of code in solution: 117
		(Feel free to use more or less, this
		is provided as a sanity check)

	Put your team members' names: Madison Rivas, Nathan Howard, Tyler Milligan



"""

import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import base64


host = "localhost"
port = 10001

# import server's public key
pub_key_string = open("../pub_key.pem","r").read()
pub_key = RSA.importKey(pub_key_string)


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
	return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function -- done
    key = os.urandom(16)
    encoded_key = base64.b64encode(key)
    return encoded_key
    pass


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
	# TODO: Implement this function -- done
	encypted_key = pub_key.encrypt(session_key, 32)
	return encypted_key[0]
	pass


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
	# TODO: Implement this function -- done
	message = pad_message(message)
	nonce = 16 * '\x00' 
	cypher = AES.new(session_key, AES.MODE_CBC, nonce)
	encrypted_message = cypher.encrypt(message)
	return encrypted_message
	pass


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
	# TODO: Implement this function
	nonce = 16 * '\x00' 
	cypher = AES.new(session_key, AES.MODE_CBC, nonce)
	decrypted_message = cypher.decrypt(message)
	decrypted_message = str(decrypted_message, 'utf-8')
	return decrypted_message


# Sends a message over TCP
def send_message(sock, message):
	sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
	data = sock.recv(1024)
	return data


def main():
	user = input("What's your username? ")
	password = input("What's your password? ")

	# Create a TCP/IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# Connect the socket to the port where the server is listening
	server_address = (host, port)
	print('connecting to {} port {}'.format(*server_address))
	sock.connect(server_address)

	try:
		# Message that we need to send
		message = user + ' ' + password

		# Generate random AES key
		key = generate_key()

		# Encrypt the session key using server's public key
		encrypted_key = encrypt_handshake(key)

		# Initiate handshake
		send_message(sock, encrypted_key)

		# Listen for okay from server (why is this necessary?)
		if receive_message(sock).decode() != "okay":
			print("Couldn't connect to server")
			exit(0)

		# TODO: Encrypt message and send to server -- done
		user_message = "User: {} Password: {}".format(user, password)
		encrypted_user_message = encrypt_message(user_message, key)
		send_message(sock, encrypted_user_message)

		# TODO: Receive and decrypt response from server
	finally:
		print('closing socket')
		sock.close()


if __name__ in "__main__":
	main()
