# -*- coding: utf-8 -*-
# Created by restran on 2017/7/17
from __future__ import unicode_literals, absolute_import

import re
from optparse import OptionParser

"""
https://github.com/abpolym/crypto-tools/tree/master/find-coding-scheme
"""

parser = OptionParser()
parser.add_option("-d", "--data str", dest="data_str", type="string",
                  help="data str")
parser.add_option("-f", "--file name", dest="file_name", type="string",
                  help="read from file")


def detect_code_scheme(e_str):
    scheme_list = []
    bin_rex = re.compile('^[01]+$', re.MULTILINE)
    if bin_rex.match(e_str):
        scheme_list.append('binary')
        # print('binary')

    oct_rex = re.compile('^[0-7]+$', re.MULTILINE)
    if oct_rex.match(e_str):
        scheme_list.append('octal')
        # print('octal')

    dec_rex = re.compile('^[0-9]+$', re.MULTILINE)
    if dec_rex.match(e_str):
        scheme_list.append('decimal')
        # print('decimal')

    hex_rex = re.compile('^[A-Fa-f0-9]+$', re.MULTILINE)
    if hex_rex.match(e_str):
        scheme_list.append('hex')
        # print('hexadecimal')

    b64rex = re.compile('^[A-Za-z0-9+/]+[=]{0,2}$', re.MULTILINE)
    if b64rex.match(e_str):
        scheme_list.append('base64')
        # print('base64')

    b32rex = re.compile('^[A-Z2-7]+[=]{0,2}$', re.MULTILINE)
    if b32rex.match(e_str):
        scheme_list.append('base32')
        # print('base32')

    b16rex = re.compile('^[A-F0-9]+[=]{0,2}$', re.MULTILINE)
    if b16rex.match(e_str):
        scheme_list.append('base16')
        # print('base16')

    uu_rex = re.compile('^(begin.*\n)?[\x20-\x60\n]+(end[\n]?)?$', re.MULTILINE)
    if uu_rex.match(e_str):
        scheme_list.append('uuencode')
        # print('uuencode')

    intel_hex_rex = re.compile('^:[0-9a-fA-F]{8}[0-9a-fA-F]*[0-9a-fA-F]{2}$', re.MULTILINE)
    if intel_hex_rex.match(e_str):
        scheme_list.append('intel_hex')
        # print('intelhex')

    srec_rex = re.compile('^S[0-9]{1}[0-9a-fA-F]{6,10}[0-9a-fA-F]*[0-9a-fA-F]{2}$')
    if srec_rex.match(e_str):
        scheme_list.append('srec')
        # print('srec')

    # ascii85 也叫做 base85
    ascii85rex = re.compile('^[A-Za-z0-9!#$%&()*+\-;<=>?@^_`{|}~]+$', re.MULTILINE)
    if ascii85rex.match(e_str):
        scheme_list.append('ascii85')
        # print('ascii85')

    bin_hex_rex = re.compile(r'^[A-NP-VX-Z0-9a-fh-mp-r\!\"\#\$\%\&\'\(\)\*\+\,\-\@\`\[\:]+$', re.MULTILINE)
    if bin_hex_rex.match(e_str):
        scheme_list.append('bin_hex_rex')
        # print('binhexrex')

    xx_rex = re.compile('^[A-Za-z0-9+\-]+$')
    if e_str.startswith('begin'):
        t_str = e_str.split('\n')
        t_str = ''.join(t_str[1:len(t_str) - 1])
        if xx_rex.match(t_str):
            scheme_list.append('xxencode')
            # print('xxencode')
    if xx_rex.match(e_str):
        if 'xxencode' not in scheme_list:
            scheme_list.append('xxencode')
            # print('xxencode')

    md5rex = re.compile('^[0-9a-fA-F]{32}$')
    if md5rex.match(e_str):
        scheme_list.append('md5')
        # print('md5')

    sha0and1rex = re.compile('^[0-9a-fA-F]{40}$')
    if sha0and1rex.match(e_str):
        scheme_list.append('sha-0 or sha-1')
        # print('sha-0 or sha-1')

    sha224 = re.compile('^[0-9a-fA-F]{56}$')
    if sha224.match(e_str):
        scheme_list.append('sha-224')
        # print('sha-224')

    sha256 = re.compile('^[0-9a-fA-F]{64}$')
    if sha256.match(e_str):
        scheme_list.append('sha-256')
        # print('sha-256')

    sha384 = re.compile('^[0-9a-fA-F]{96}$')
    if sha384.match(e_str):
        scheme_list.append('sha-384')
        # print('sha-384')

    sha512 = re.compile('^[0-9a-fA-F]{128}$')
    if sha512.match(e_str):
        scheme_list.append('sha-512')
        # print('sha-512')

    shadow_code = re.compile('^[01248]+$')
    if shadow_code.match(e_str):
        scheme_list.append('shadow code')

    if e_str.startswith('PYIIIIIIIIII'):
        scheme_list.append('win32 shellcode')

    if len(set(e_str)) == 5 and len(e_str) % 5 == 0:
        scheme_list.append('只有5种字符：波利比奥斯方阵密码（可以先统计字符频率）')

    return scheme_list


def main():
    (options, args) = parser.parse_args()

    if options.data_str is not None:
        data_str = options.data_str
    elif options.file_name is not None:
        with open(options.file_name, 'rb') as f:
            data_str = f.read()
    else:
        parser.print_help()
        return

    scheme_list = detect_code_scheme(data_str)
    print('\n'.join(scheme_list))


if __name__ == '__main__':
    main()
