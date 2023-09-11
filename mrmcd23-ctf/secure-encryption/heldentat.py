#!/usr/bin/env python3
import requests
import base64
import re

url = "https://ctf.mrmcd.net/rc4/"
flag_enc_b64 = "UNw8RWv9gLe7Aiv6nqkEkxOvCD1OJEeG8+/Zq463mYvEDkccqQ=="

search_range = [0x20, 0x7E + 1]

def encrypt(data):
    response = requests.get(url, data={"Plaintext": data})
    key = re.search(r"Your encrypted text:</p>(.*)", response.content.decode("utf-8")).group(1)
    return base64.b64decode(key)

def decrypt(encrypted_b64):
    enc = base64.b64decode(encrypted_b64)
    dec = b""

    for idx in range(len(enc)):
        for letter in range(*search_range):
            _tmp = dec + bytes([letter])

            if encrypt(_tmp) == enc[:idx + 1]:
                dec = _tmp
                break
        assert len(dec) == idx + 1
        print(f"partial flag is: {dec}")

print(f"Starting decryption for {flag_enc_b64}")
decrypt(flag_enc_b64)
