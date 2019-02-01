# Credentials.yml.enc Decryptor
An "off-the-rails" (python) implementation for decrypting and encrypting **_credentials.yml.enc_** files.

## Background
"credentials.yml.enc" files are the new norm for storing Ruby on Rails ( >= v5.2) secrets in a secure way.<br/>
The credential file is encrypted using AES-GCM, and the encryption key stored in the master.key file.<br/>

## Usage
### Decryption
```
$ python decryptor.py credentials.yml.enc master.key
```

### Encryption
```
$ python encryptor.py credentials.yml master.key
```

## Requires
- python
- pyca (https://github.com/pyca/cryptography)

## To Do
- Working on python 3 compatibility
