# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import hashlib
import sys


def main():
    file_name = sys.argv[1]

    with open(file_name, 'rb') as f:
        data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        print('md5   : %s' % md5)
        print('sha1  : %s' % sha1)
        print('sha256: %s' % sha256)


if __name__ == '__main__':
    main()
