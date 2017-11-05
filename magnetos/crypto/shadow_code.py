# -*- coding: utf-8 -*-
# Created by restran on 2017/9/15
from __future__ import unicode_literals, absolute_import

"""
影子密码

请分析下列密文进行解密 8842101220480224404014224202480122 得到flag，flag为8位大写字母

有7个0，拆开得到8个字符，然后把这些数字加起来，得到8个数字，表示26个字母中第几个字母
88421 0 122 0 48 0 2244 0 4 0 142242 0 248 0 122
23    5    12    12    4    15    14  5
"""

import string


def decode(data):
    data = data.strip()
    split_list = data.split('0')
    data = [sum([int(t) for t in item]) for item in split_list]

    result = ''
    for i in data:
        result += string.ascii_uppercase[i - 1]

    return result


def main():
    d = '8842101220480224404014224202480122'
    r = decode(d)
    print(r)


if __name__ == '__main__':
    main()
