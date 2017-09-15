# -*- coding: utf-8 -*-
# Created by restran on 2017/7/17
from __future__ import unicode_literals, absolute_import
from mountains.encoding import force_bytes

cipher_letters = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def decode(data, length=None, print_output=True):
    new_data = []
    for t in data:
        i = cipher_letters.index(t)
        new_data.append(i)

    data_list = []
    while len(new_data) > 0:
        t = new_data[:4]
        if len(t) < 4:
            t.extend([0 for i in range(4 - len(t))])

        new_data = new_data[4:]
        data_list.append(t)

    new_data_list = []
    for group in data_list:
        tmp_group = ['%06d' % int(bin(t)[2:]) for t in group]
        tmp_group = ''.join(tmp_group)
        new_data_list.append(tmp_group)

    result_bin_data = ''.join(new_data_list)

    decode_str = hex(int(result_bin_data, 2))[2:].rstrip('L')
    # print(decode_str)
    if length is not None:
        # print(len(decode_str))
        decode_str = decode_str[:length * 2]
    decode_str = force_bytes(decode_str).decode('hex')
    if print_output:
        print(decode_str)

    return decode_str


def decode_chacuo(data):
    """
    这个网站的实现中 http://web.chacuo.net/charsetxxencode/
    每60个字符输出一行，然后在开始位置加上1个字符存储长度
    :param data:
    :return:
    """
    result = []

    data = data.replace('\n', '').replace(' ', '').strip()
    print(data)
    length = 61
    data_list = []
    while len(data) > 0:
        data_list.append(data[:length])
        data = data[length:]

    for t in data_list:
        length = cipher_letters.index(t[0])
        # print(length)
        result.append(decode(t[1:], length, print_output=False))

    output = b''.join(result)
    try:
        print('utf8编码:')
        print(output)
    except:
        pass

    try:
        print('gb2312编码:')
        print(output.decode('gb2312'))
    except:
        pass


def main():
    data = """U2FsdGVkX18vmjE0tvWk69TBu9inuiNnM3rBhsu6tXzLhu+"""
    # data = 'LNalVNrhIO4ZnLqZnLpVsAqtXA4FZTEc+'
    decode_chacuo(data)


if __name__ == '__main__':
    main()
