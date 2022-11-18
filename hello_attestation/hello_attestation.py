#/bin/python3
#-*- coding: utf-8 -*-

import sys
import time
import base64
import json
import extract_attestation

sys.path.append("/app")
import pyattestation as pya
import cryptography
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

counter = 1
while True:
    time.sleep(1)
    print("......")
    counter = counter + 1
    if counter > 10:
        break

print("begin to get attestation")    
a = pya.attestation()
print("begin to genreate the key")
isKey = a.init_key_pair()

user_data = "this is a attestation demo"
user_nounce = str(4120717569636)
print("begin to get attestation doc")
att_doc = a.request_attestation_doc(user_data, user_nounce)
att_json = json.loads(att_doc)
att_content = att_json["AttestationDocument"]
att_bytes = base64.b64decode(att_content)

sigalg, attdoc, docsig = extract_attestation.get_all_items(att_bytes)

print("begin to load public key")
pub_key = serialization.load_der_public_key(base64.b64decode(attdoc["public_key"].encode()), backend=default_backend())

message = b'hello nitro enclave'

print("begin to encrypt")
ciphertext = pub_key.encrypt( message, padding.PKCS1v15())

#plaintext2 = a.decrypt_data_with_private_key(base64.b64encode(ciphertext).decode())

print("begin to get pub key")
public_key_str = a.get_public_key()
print("begin to get private key")
private_key_str = a.get_private_key()
private_key = serialization.load_der_private_key(base64.b64decode(private_key_str), password=None, backend=default_backend())

plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())

print(message, plaintext)

while True:
    print(sigalg, docsig)
    time.sleep(5)
    