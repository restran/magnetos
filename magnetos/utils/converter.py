# -*- coding: utf-8 -*-
"""
Created on 2017/9/14
"""

from __future__ import unicode_literals, absolute_import

import base64
import binascii


def base64_padding(data):
    if len(data) % 4 != 0:
        data = '%s%s' % (data, '=' * (4 - len(data) % 4))
    return data


def to_hex(data):
    """
    把一个字符串转成其ASCII码的16进制表示
    :param data: 要转换的字符串
    :return: ASCII码的16进制表示字符串
    """
    return binascii.b2a_hex(data)


def from_hex(data):
    """
    把十六进制字符串转换成其ASCII表示字符串
    :param data: 十六进制字符串
    :return: 字符串
    """
    return binascii.a2b_hex(data)


def to_base64(data):
    """
    把字符串转换成BASE64编码
    :param data: 字符串
    :return: BASE64字符串
    """
    return base64.b64encode(data)


def from_base64(data):
    """
    解base64编码
    :param data: base64字符串
    :return: 字符串
    """
    data = base64_padding(data)
    return base64.b64decode(data)


def to_base32(data):
    """
    把字符串转换成BASE32编码
    :param data: 字符串
    :return: BASE32字符串
    """
    return base64.b32encode(data)


def from_base32(data):
    """
    解base32编码
    :param data: base32字符串
    :return: 字符串
    """
    data = base64_padding(data)
    return base64.b32decode(data)


def to_base16(data):
    """
    把字符串转换成BASE16编码
    :param data: 字符串
    :return: BASE16字符串
    """
    return base64.b16encode(data)


def from_base16(data):
    """
    解base16编码
    :param data: base16字符串
    :return: 字符串
    """
    return base64.b16decode(data)


def to_uu(data):
    """
    uu编码
    :param data: 字符串
    :return: 编码后的字符串
    """
    return binascii.b2a_uu(data)


def from_uu(data):
    """
    解uu编码
    :param data: uu编码的字符串
    :return: 字符串
    """
    return binascii.a2b_uu(data)


def str2hex(s):
    return binascii.b2a_hex(s)


def hex2str(s):
    return from_hex(s)


base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]


# bin2dec
# 二进制 to 十进制: int(str,n=10)
def bin2dec(string_num):
    return str(int(string_num, 2))


# dec2bin
# 十进制 to 二进制: bin()
def dec2bin(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0:
            break
        num, rem = divmod(num, 2)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])


# hex2dec
# 十六进制 to 十进制
def hex2dec(string_num):
    return str(int(string_num.upper(), 16))


# dec2hex
# 十进制 to 八进制: oct()
# 十进制 to 十六进制: hex()
def dec2hex(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0:
            break
        num, rem = divmod(num, 16)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])


# hex2tobin
# 十六进制 to 二进制: bin(int(str,16))
def hex2bin(string_num):
    return dec2bin(hex2dec(string_num.upper()))


# bin2hex
# 二进制 to 十六进制: hex(int(str,2))
def bin2hex(string_num):
    return dec2hex(bin2dec(string_num))


if __name__ == "__main__":
    pass
