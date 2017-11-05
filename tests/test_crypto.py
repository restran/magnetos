# -*- coding: utf-8 -*-
# Created by restran on 2017/10/15
from __future__ import unicode_literals, absolute_import
import os
import unittest
import logging
from magnetos.crypto import mobile_keyboard

logger = logging.getLogger(__name__)


class CryptoTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_mobile_keyboard(self):
        s = '1F'
        r = converter.hex2dec(s)
        self.assertEqual(r, '31')
        s = '1F1F'
        r = converter.hex2dec(s)
        self.assertEqual(r, '7967')




if __name__ == '__main__':
    unittest.main()