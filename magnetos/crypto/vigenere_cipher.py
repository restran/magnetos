# -*- coding: utf-8 -*-
from __future__ import unicode_literals

"""
维吉尼亚密码破解
"""
from pycipher import Vigenere
from magnetos.utils import get_raw_plain_text

import re

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def find_key_by_plain_cipher(plain, cipher):
    # key = 'qpilfrvkvcrzx'

    # cipher = '''jwm ewrboya fe gjbxcd hrzcvt.'''
    # plain = '''the tragedy of julius caesar.'''

    cipher = re.sub(r'[^A-Z]', '', cipher.upper())
    plain = re.sub(r'[^A-Z]', '', plain.upper())

    key = ''
    for i in range(len(cipher)):
        for x in LETTERS:
            if Vigenere(key + x).decipher(cipher)[i] == plain[i]:
                key += x
                break

    key = key.lower()
    print(key)
    return key


def decrypt(cipher, key):
    plain = Vigenere(key).decipher(cipher)
    print(get_raw_plain_text(cipher, plain))


def main():
    cipher = """jwm ewrboya fe gjbxcd hrzcvt."""
    plain = """the tragedy of julius caesar."""
    key = find_key_by_plain_cipher(plain, cipher)
    decrypt(cipher, key)


if __name__ == '__main__':
    main()
