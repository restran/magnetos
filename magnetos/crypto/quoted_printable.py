# -*- coding: utf-8 -*-
# Created by restran on 2017/7/17
from __future__ import unicode_literals, absolute_import
import quopri
from mountains.util import PrintCollector

"""
Quoted-printable 编码

它是多用途互联网邮件扩展（MIME) 一种实现方式。有时候我们可以邮件头里面能够看到这样的编码
"""


def decode(data):
    data = quopri.decodestring(data)
    p = PrintCollector()
    # 原始的数据可能是用不同的编码
    try:
        p.print('decode as utf8:')
        p.print(data)
    except:
        pass

    try:
        p.print('decode as gb2312:')
        p.print(data.decode('gb2312'))
    except:
        pass

    return p.all_output()


def encode(data):
    data = quopri.decodestring(data)
    print(data)
    return data


def main():
    data = """=B9=A7=CF=B2=C4=FA"""
    decode(data)


if __name__ == '__main__':
    main()
