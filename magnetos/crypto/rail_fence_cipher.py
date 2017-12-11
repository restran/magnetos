#!/usr/bin/env python
# -*- coding: utf_8 -*-
# Author: 蔚蓝行
from __future__ import unicode_literals
from mountains.utils import PrintCollector

"""
破解栅栏密码python脚本
"""


def decode(e):
    p = PrintCollector()
    # e = 'tn c0afsiwal kes,hwit1r  g,npt  ttessfu}ua u  hmqik e {m,  n huiouosarwCniibecesnren.'
    data = len(e)
    field = []
    for i in range(2, data):
        if data % i == 0:
            field.append(i)

    for f in field:
        b = data // f
        r = {x: '' for x in range(b)}
        for i in range(data):
            a = i % b
            r.update({a: r[a] + e[i]})
        d = ''
        for i in range(b):
            d = d + r[i]
        x = '分为\t' + str(f) + '\t' + '栏时，解密结果为: ' + d
        p.print(x)

    return p.all_output()


def main():
    # 栅栏密码特点就是隔几个字母能读顺成一个单词，一般译为分2个一组
    # 具体情况具体分析，有的题目特殊，会出现某个地方是单独三个一组
    # e = 'T_ysK9_5rhk__uFMt}3El{nu@E'
    e = """U8Y]:8KdJHTXRI>XU#?!K_ecJH]kJGbRH7YJH7YSH]=93dVZ3^S8$:8"&:9U]RH;g=8Y!U92'=j$KH]ZSj&[S#!gU#*dK9."""
    decode(e)


if __name__ == '__main__':
    main()
