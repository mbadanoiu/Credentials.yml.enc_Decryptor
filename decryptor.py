#!/usr/bin/python3

import os
import base64
import sys
import codecs

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def print_help():
	sys.stdout.write("\n\tUsage: " + sys.argv[0] + " <path_credentials.yml.enc> <path_master.key>\n\n")
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

def uncredentify(credentials_yml_enc):
	separator = "--"
	ciphertext_b64, iv_b64, tag_b64 = credentials_yml_enc.split(separator)
	ciphertext = base64.b64decode(ciphertext_b64)
	iv = base64.b64decode(iv_b64)
	tag = base64.b64decode(tag_b64)
	return (ciphertext, iv, tag)

def unmasterify(master_key):
    return codecs.decode(master_key, 'hex')

def decrypt(key, iv, ciphertext, tag):
	# Construct a Cipher object, with the key, iv, and additionally the
	# GCM tag used for authenticating the message.
	decryptor = Cipher(
	algorithms.AES(key),
	modes.GCM(iv, tag),
	backend=default_backend()
	).decryptor()

	# Decryption gets us the authenticated plaintext.
	# If the tag does not match an InvalidTag exception will be raised.
	return decryptor.update(ciphertext) + decryptor.finalize()

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

	key = unmasterify(master)
	ciphertext, iv, tag = uncredentify(cred)

	dec = decrypt(
		key,
		iv,
		ciphertext,
		tag)

	print(dec)
