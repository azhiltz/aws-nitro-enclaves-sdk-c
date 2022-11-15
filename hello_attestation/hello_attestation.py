#/bin/python3
#-*- coding: utf-8 -*-

import sys
import time
import base64
import json
import extract_attestation

sys.path.append("/app")
import pyattestation as pya

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
att_doc = a.request_attestation_default_doc()
att_json = json.loads(att_doc)
att_content = att_json["AttestationDocument"]
att_bytes = base64.b64decode(att_content)

sigalg, attdoc, docsig = extract_attestation.get_all_items(att_bytes)
print(attdoc)

while True:
    print(sigalg, docsig)
    time.sleep(5)
    