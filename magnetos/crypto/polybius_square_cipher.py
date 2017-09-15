# -*- coding: utf-8 -*-
# Created by restran on 2017/7/17
from __future__ import unicode_literals, absolute_import
from copy import deepcopy
import string

"""
波利比奥斯方阵密码（Polybius Square Cipher或称波利比奥斯棋盘）是棋盘密码的一种，
是利用波利比奥斯方阵进行加密的密码方式，简单的来说就是把字母排列好，用坐标(行列)的形式表现出来。
字母是密文，明文便是字母的坐标。
"""

# 这里去掉了 j
cipher_str = 'abcdefghiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def decode_char(x, y):
    # 检测是否为特殊的 i 和 j
    special = False
    if (x, y) == (2, 4):
        special = True

    c = cipher_str[(x - 1) * 5 + y - 1]

    return special, c


def decode(data):
    new_data = list(data)
    result_list = [[]]
    while len(new_data) > 0:
        t = new_data[:2]
        if len(t) < 2 or not (t[0] in string.digits and t[1] in string.digits):
            for x in result_list:
                x.append(t[0])
            new_data = new_data[1:]
            continue
        else:
            new_data = new_data[2:]

        # 因为 i 和 j 共用了一个编码，所以这里遍历所有可能
        special, c = decode_char(int(t[0]), int(t[1]))
        if special:
            tmp_result_list = deepcopy(result_list)
            for x in tmp_result_list:
                x.append('j')
            for x in result_list:
                x.append(c)
            result_list.extend(tmp_result_list)
        else:
            for x in result_list:
                x.append(c)

    new_result_list = []
    for x in result_list:
        x = ''.join(x)
        new_result_list.append(x)
        print(x)
    return new_result_list


def detect(data):
    data = [t for t in data if t in string.hexdigits]
    for t in data:
        if t not in ['1', '2', '3', '4', '5']:
            print('可能波利比奥斯方阵密码')
            return False

    return True


def main():
    # data = '3534315412244543_434145114215_132435231542'
    data = '54433252224455342251522244342223113412'
    detect(data)
    decode(data)


if __name__ == '__main__':
    main()
