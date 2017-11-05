# -*- coding: utf-8 -*-
# Created by restran on 2017/7/3

from __future__ import unicode_literals
from mountains.util import PrintCollector

""""
奇偶移位不同的凯撒
"""


def decode(data, verbose=True):
    p = PrintCollector()
    for i in range(26):
        key = ''
        for x in data:
            s = ord(x)
            if (s not in range(97, 123)) and (s not in range(65, 91)):
                key = key + chr(s)
            else:
                # print chr(s)
                if s in range(97, 123):
                    if s % 2 == 0:
                        s = s - i
                        if s not in range(97, 123):
                            t = 97 - s
                            t = 123 - t
                            key = key + chr(t)
                        else:
                            key = key + chr(s)
                    else:
                        s = s + i
                        if s not in range(97, 123):
                            t = s - 122 + 96
                            key = key + chr(t)
                        else:
                            key = key + chr(s)
                else:
                    # print chr(s)
                    if s % 2 == 0:
                        s = s - i
                        if s not in range(65, 91):
                            t = 65 - s
                            t = 91 - t
                            key = key + chr(t)
                        else:
                            key = key + chr(s)
                    else:
                        s = s + i
                        if s not in range(65, 91):
                            t = s - 90 + 64
                            key = key + chr(t)
                        else:
                            key = key + chr(s)
        p.print(key)

    return

if __name__ == '__main__':
    # d = "vbkq{ukCkS_vrduztucCVQXVuvzuckrvtZDUBTGYSkvcktv}"
    d = "DISJV_Hej_UdShofjyed"
    decrypt(d)
