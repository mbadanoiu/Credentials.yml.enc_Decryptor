#!/usr/bin/python3

import os
import base64
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def print_help():
	sys.stdout.write("\n\tUsage: " + sys.argv[0] + " <path_credentials.yml> <path_master.key>\n\n")
	quit()

def file_doesnt_exist(file_path):
	if not os.path.isfile(file_path):
		sys.stdout.write("\n\tFile " + file_path + " doesn't exist\n\n")
		quit()

def file_read(file_path):
	f = open(file_path, 'r')
	content = f.read().rstrip()
	f.close()
	return content

def credentify(ciphertext, iv, tag):
	separator = b"--"
	ciphertext_b64 = base64.b64encode(ciphertext)
	iv_b64 = base64.b64encode(iv)
	tag_b64 = base64.b64encode(tag)
	res = ciphertext_b64 + separator + iv_b64 + separator + tag_b64
	return res.decode('utf-8')

def unmasterify(master_key):
	try:
		return master_key.decode('hex')
	except:
		1+1
	try:
		return bytes.fromhex(master_key)
	except:
		1+1
	print("Something happened -- Windows")
	quit()

def encrypt(key, plaintext):
	# Generate a random 96-bit IV.
	iv = os.urandom(12)

	# Construct an AES-GCM Cipher object with the given key and a
	# randomly generated IV.
	encryptor = Cipher(
	algorithms.AES(key),
	modes.GCM(iv),
	backend=default_backend()
	).encryptor()

	# Encrypt the plaintext and get the associated ciphertext.
	# GCM does not require padding.
	ciphertext = encryptor.update(plaintext) + encryptor.finalize()

	return (iv, ciphertext, encryptor.tag)

def init():
	if len(sys.argv) != 3:
		print_help()

	cred_file = sys.argv[1]
	master_file = sys.argv[2]

	file_doesnt_exist(cred_file)
	file_doesnt_exist(master_file)

	cred = file_read(cred_file)
	master = file_read(master_file)

	return (cred, master)

if __name__ == "__main__":
	cred, master = init()

	plaintext = cred
#	plaintext = bytes(cred, 'utf-8')
	key = unmasterify(master)

	iv, ciphertext, tag = encrypt(
	    key,
	    plaintext)

	print(credentify(ciphertext, iv, tag))
