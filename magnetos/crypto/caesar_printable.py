# -*- coding: utf-8 -*-
from __future__ import unicode_literals

"""
凯撒密码，实现 33-126 ASCII 可打印的字符循环平移  
"""


def convert(c, key):
    num = ord(c)
    if 33 <= num <= 126:
        # 126-33=93
        num = 33 + (num + key - 33) % 94
    return chr(num)


def caesar_encode(s, key):
    o = ""
    for c in s:
        o += convert(c, key)
    return o


def caesar_decode(s, key):
    return caesar_encode(s, -key)


def main():
    for key in range(94):
        s = """U8Y]:8KdJHTXRI>XU#?!K_ecJH]kJG*bRH7YJH7YSH]*=93dVZ3^S8*$:8"&:9U]RH;g=8Y!U92'=j*$KH]ZSj&[S#!gU#*dK9\."""
        # e = caesar_encode(s, key)
        d = caesar_decode(s, key)
        print(d)


if __name__ == '__main__':
    main()
