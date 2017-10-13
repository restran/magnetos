# -*- coding: utf-8 -*-
# Created by restran on 2017/10/13
from __future__ import unicode_literals, absolute_import
import os
import unittest
import logging
from magnetos.util import converter
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


if __name__ == '__main__':
    unittest.main()
