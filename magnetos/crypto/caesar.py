# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from ..crypto import smart_output
from mountains.util import PrintCollector

"""
破解凯撒密码python脚本
"""


def convert(c, key, start='a', n=26):
    a = ord(start)
    offset = ((ord(c) - a + key) % n)
    return chr(a + offset)


def encode(s, key):
    o = ""
    for c in s:
        if c.islower():
            o += convert(c, key, 'a')
        elif c.isupper():
            o += convert(c, key, 'A')
        else:
            o += c
    return o


def decode(s, key):
    return encode(s, -key)


def decode_all(data, verbose=True):
    p = PrintCollector()
    for key in range(26):
        r = decode(data, key)
        p.print(r)
    return smart_output(p.collector, verbose, p)


def main():
    s = 'tedr{ykdd_dyckl_xvpdfyy3sbve8_c7l0f}'
    decode_all(s)


if __name__ == '__main__':
    main()
