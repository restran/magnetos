# -*- coding: utf-8 -*-
# Created by restran on 2017/9/15
from __future__ import unicode_literals, absolute_import
import string
import subprocess


def run_shell_cmd(cmd):
    try:
        (stdout, stderr) = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, shell=True).communicate()
        if stdout is None:
            stdout = ''
        if stderr is None:
            stderr = ''
        return '%s%s' % (stdout, stderr)

    except Exception as e:
        print(e)
        print('!!!error!!!')
        return ''


def get_raw_plain_text(raw_data, decoded_data):
    """
    因为密文中可能包含数字，符合等各种非字母的字符，一些解密的算法是不考虑这些
    在输出明文的时候，要跟这些符合，按要原来的顺序还原回来
    :param raw_data:
    :param decoded_data:
    :return:
    """
    index = 0
    plain = []
    for i, c in enumerate(raw_data):
        if c in string.ascii_lowercase:
            new_c = decoded_data[index].lower()
            index += 1
        elif c in string.ascii_uppercase:
            new_c = decoded_data[index].upper()
            index += 1
        else:
            new_c = c

        plain.append(new_c)

    return ''.join(plain)
