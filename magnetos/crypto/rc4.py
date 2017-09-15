# -*- coding: utf-8 -*-
# Created by restran on 2016/12/4
# https://github.com/RyanKung/rc4-python3/blob/master/rc4/rc4.py

import random
import base64
import json
from typing import Callable
from hashlib import sha1

__all__ = ['encrypt', 'decrypt', 'encrypt_json', 'decrypt_json']


def crypt(data: str, key: bytes) -> str:
    """RC4 algorithm"""
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + int(box[i]) + int(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)


def encrypt(data: str, key: str, encode: Callable = base64.b64encode, salt_length: int = 16) -> str:
    """RC4 encryption with random salt and final encoding"""
    salt = ''
    for n in range(salt_length):
        salt += chr(random.randrange(256))
    data = salt + crypt(data, sha1((key + salt).encode()).digest())
    if encode:
        data = encode(data.encode())
    return data


def decrypt(data: str, key: str, decode: Callable = base64.b64decode, salt_length: int = 16) -> str:
    """RC4 decryption of encoded data"""
    if decode:
        data = decode(data).decode()
    salt = data[:salt_length]
    return crypt(data[salt_length:], sha1((key + salt).encode()).digest())


def encrypt_json(data: dict, key: str) -> str:
    return encrypt(json.dumps(data), key)


def decrypt_json(data: str, key: str) -> dict:
    return json.loads(decrypt(data, key))


def main():
    """
    >>> for i in range(10):
    ...    msg = 'secret message'
    ...    encryptd = encrypt(msg, 'my-key')
    ...    decryptd = decrypt(encryptd, 'my-key')
    ...    msg == decryptd
    True
    True
    True
    True
    True
    True
    True
    True
    True
    True
    """
    import doctest

    doctest.testmod()
    # import sys
    # argv = sys.argv
    # if argv[1] == 'encrypt':
    #     return encrypt(argv[2], argv[3]).encode().decode()
    # if argv[1] == 'decrypt':
    #     return decrypt(argv[2], argv[3])
    # else:
    #     return '''Options:
    #     pyrc4 encrypt data key
    #     pyrc4 decrypt data key'''

    # 需要加密的数据
    data = 'UUyFTj8PCzF6geFn6xgBOYSvVTrbpNU4OF9db9wMcPD1yDbaJw=='
    # 密钥
    key = 'welcometoicqedu'

    # 加码
    encoded_data = encrypt(data=data, key=key)
    print(encoded_data)
    # 解码
    decoded_data = decrypt(data=encoded_data, key=key)
    print(decoded_data)


if __name__ == '__main__':
    main()
