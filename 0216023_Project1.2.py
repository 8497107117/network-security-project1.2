import socket
import sys
import struct
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Produce client private key and export as PEM file
# 1. Generate the RSA Private Key ( the RSA PRivate key is a object containing both private key and public key )
# The following 2nd and 3rd step are not necessary to be done
	# 2. Transform the RSA Private key to it's PEM format
	# 3. Write the PEM format into the PEM file

# Produce client public key and export as PEM file
# 1. Get the RSA Public Key from the object - RSA PRivate key
# 2. Transform the RSA Public key to it's PEM format
# 3. Write the PEM format into the PEM file


# Construct a TCP socket
HOST, PORT = "140.113.194.88", 30000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
	# Connect to the server
	sock.connect((HOST, PORT))
	
	# Send hello to server
	# 1. Send the size in byte of "hello" to Server
	msg_size = len("hello")
	byte_msg_size = struct.pack("i", msg_size)
	sock.sendall( byte_msg_size )
	# 2. Send the "hello" string to Server
	sock.sendall(bytes("hello", 'utf-8'))

	# Receive Server public pem file
	# 1. Receive the size in byte of Server Public Key's PEM file from Server
	msg_size = struct.unpack('i', sock.recv(4))
	print('Length of TA\'s public key: ', msg_size[0])
	# 2. Receive Server Public Key's PEM file from Server
	TAPubKey = str(sock.recv(int(msg_size[0])), "utf-8")
	print('TA\'s public key:\n', TAPubKey)
	# 3. Write the Server's Public Key PEM file and store it
	with open('TA.pem', 'w') as f:
		f.write(TAPubKey)
		f.close()
	# Send public pem file to server
	# 1. Read the Public Key's PEM file
	with open('public.pem', 'rb') as f:
		myPubKey = serialization.load_pem_public_key(f.read(), backend=default_backend())
		f.close()
	myPubPem = myPubKey.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	print('My public key:\n', str(myPubPem, 'utf-8'))
	# 1. Send the size in byte of Public Key's PEM file to Server
	msg_size = len(str(myPubPem,'utf-8'))
	byte_msg_size = struct.pack('i', msg_size)
	sock.sendall(byte_msg_size)
	# 2. Send Public Key's PEM file to Server
	sock.sendall(myPubPem)

	# Send Student ID encrypted by Server's Public Key to Server
	# 1. Read Server Public Key's PEM file and get Server's Public Key
	with open('TA.pem', 'rb') as f:
		TAPubKey = serialization.load_pem_public_key(
			f.read(),
			backend=default_backend()
		)
		f.close()
	# 2. Use Server's Public Key to encrypt Student ID
	encryptedID = TAPubKey.encrypt(
		bytes('0216023', 'utf-8'),
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
        	label=None
		)
	)
	# 3. Send the size in byte of ciphertext to Server
	msg_size = len(encryptedID)
	byte_msg_size = struct.pack('i', msg_size)
	sock.sendall(byte_msg_size)
	# 4. Send the ciphertext to Server
	sock.sendall(encryptedID)
	
	# Receive encrypted magic number
	# 1. Receive the size of encrypted magic bnumber from Server
	msg_size = struct.unpack('i', sock.recv(4))
	print('Length of encrypted magic number: ', msg_size[0])
	# 2. Receive encrypted magic bnumber from Server
	encryptedMagicNum = sock.recv(int(msg_size[0]))
	print('Encrypted magic number:\n', encryptedMagicNum)
	# 3. Decrypt the encrypted magic bnumber by client's RSA Private Key
	with open('private.pem', 'rb') as f:
		myPriKey = serialization.load_pem_private_key(
			f.read(),
			password=None, 
			backend=default_backend()
		)
		f.close()
	magicNumber = myPriKey.decrypt(
	    encryptedMagicNum,
	    padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
	        label=None
	    )
	)
	print(magicNumber)

	# Receive Bye
	# 1. Receive the size in byte of bye-message from Server
	msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive bye-message from Server
	received = str(sock.recv(int(msg_size[0])), "utf-8")

	print(received)
