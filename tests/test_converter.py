# -*- coding: utf-8 -*-
# Created by restran on 2017/10/13
from __future__ import unicode_literals, absolute_import
import os
import unittest
import logging
from magnetos.utils import converter

logger = logging.getLogger(__name__)


class ConverterTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_hex2dec(self):
        s = '1F'
        r = converter.hex2dec(s)
        self.assertEqual(r, '31')
        s = '1F1F'
        r = converter.hex2dec(s)
        self.assertEqual(r, '7967')

    def test_dec2hex(self):
        s = '31'
        r = converter.dec2hex(s)
        self.assertEqual(r.upper(), '1F')
        s = '7967'
        r = converter.dec2hex(s)
        self.assertEqual(r.upper(), '1F1F')

    def test_bin2dec(self):
        s = '11111'
        r = converter.bin2dec(s)
        self.assertEqual(r, '31')

    def test_dec2bin(self):
        s = '31'
        r = converter.dec2bin(s)
        self.assertEqual(r, '11111')

    def test_to_digital(self):
        for i in range(10, 1000):
            for j in range(2, 10):
                r = converter.to_digital(i, j)
                x = converter.from_digital(r, j)
                self.assertEqual(str(i), x)

    def test_partial_base64(self):
        x = 'ZmxhZ3t0aGlzIGlzIGEgZmxhZ30=ZmxhZ3t0aGlzIGlzIGEgZmxhZ30='
        x = converter.partial_base64_decode(x)
        self.assertEqual(x, b'flag{this is a flag}flag{this is a flag}')
        x = 'YWJjZGVmZw'
        x = converter.partial_base64_decode(x)
        self.assertEqual(x, b'abcdefg')

    def test_partial_base32(self):
        x = 'JVDFER2HHU6T2==='
        x = converter.partial_base32_decode(x)
        self.assertEqual(x, b'MFRGG===')
        x = 'MFRGG'
        x = converter.partial_base32_decode(x)
        self.assertEqual(x, b'abc')


if __name__ == '__main__':
    unittest.main()
