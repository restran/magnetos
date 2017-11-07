# -*- coding: utf-8 -*-
# Created by restran on 2017/9/26
from __future__ import unicode_literals, absolute_import


def fixed_length_split(data, width):
    """
    固定长度分割字符串
    :param data:
    :param width:
    :return:
    """
    # 使用正则的方法
    # import re
    # split = re.findall(r'.{%s}' % width, string)
    return [data[x: x + width] for x in range(0, len(data), width)]


