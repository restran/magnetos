# -*- coding: utf-8 -*-
"""
Created on 2017/9/14
"""

from __future__ import unicode_literals, absolute_import

import base64
import binascii
from base64 import b64decode, b32decode, b16decode
from mountains.encoding import utf8


def base_padding(data, length=4):
    if len(data) % length != 0:
        data = '%s%s' % (data, '=' * (length - len(data) % length))

    data = utf8(data)
    return data


def partial_decode(decode_method, data, base_padding_length=4):
    """
    对前面可以解码的数据一直解到无法解码
    :param base_padding_length:
    :param decode_method:
    :param data:
    :return:
    """
    data = utf8(data)
    result = []
    while len(data) > 0:
        tmp = base_padding(data[:base_padding_length], base_padding_length)
        data = data[base_padding_length:]
        try:
            r = decode_method(tmp)
            result.append(r)
        except:
            break
    return b''.join(result)


def partial_base64_decode(data):
    return partial_decode(b64decode, data, 4)


def partial_base32_decode(data):
    return partial_decode(b32decode, data, 3)


def partial_base16_decode(data):
    return partial_decode(b16decode, data, 2)


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
    data = base_padding(data, 4)
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
    data = base_padding(data, 3)
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
    """
    把一个字符串转成其ASCII码的16进制表示
    :param s: 要转换的字符串
    :return: ASCII码的16进制表示字符串
    """
    return binascii.b2a_hex(s)


def hex2str(s):
    """
    把十六进制字符串转换成其ASCII表示字符串
    :param s: 十六进制字符串
    :return: 字符串
    """
    return binascii.a2b_hex(s)


base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]


# bin2dec
# 二进制 to 十进制: int(str,n=10)
def bin2dec(s):
    return str(int(s, 2))


# dec2bin
# 十进制 to 二进制: bin()
def dec2bin(s):
    num = int(s)
    mid = []
    while True:
        if num == 0:
            break
        num, rem = divmod(num, 2)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])


# hex2dec
# 十六进制 to 十进制
def hex2dec(s):
    return str(int(s.upper(), 16))


# dec2hex
# 十进制 to 八进制: oct()
# 十进制 to 十六进制: hex()
def dec2hex(s):
    num = int(s)
    mid = []
    while True:
        if num == 0:
            break
        num, rem = divmod(num, 16)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])


# hex2tobin
# 十六进制 to 二进制: bin(int(str,16))
def hex2bin(s):
    return dec2bin(hex2dec(s.upper()))


# bin2hex
# 二进制 to 十六进制: hex(int(str,2))
def bin2hex(s):
    return dec2hex(bin2dec(s))


def str2num(s):
    """
    String to number.
    """
    if not len(s):
        return 0
    return int(s.encode('hex'), 16)


def num2str(n):
    """
    Number to string.
    """
    s = hex(n)[2:].rstrip('L')
    if len(s) % 2 != 0:
        s = '0' + s
    return s.encode().decode('hex')


def str2bin(s):
    """
    String to binary.
    """
    ret = []
    for c in s:
        ret.append(bin(ord(c))[2:].zfill(8))
    return ''.join(ret)


def bin2str(b):
    """
    Binary to string.
    """
    ret = []
    for pos in range(0, len(b), 8):
        ret.append(chr(int(b[pos:pos + 8], 2)))
    return ''.join(ret)


if __name__ == "__main__":
    pass
