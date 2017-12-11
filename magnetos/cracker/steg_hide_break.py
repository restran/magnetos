# -*- coding: utf-8 -*-
# Created by restran on 2017/11/5
from __future__ import unicode_literals, absolute_import

import subprocess
import sys
from magnetos.utils import run_shell_cmd

"""
steghide 隐写的密码爆破
"""


def main():
    if len(sys.argv) == 3:
        file_name = sys.argv[1]
        word_list_name = sys.argv[2]

    else:
        print("Using => python steg_hide_cracker.py [file] [wordlist]")
        sys.exit()

    file_name = file_name.strip()
    file = word_list_name
    word_list = open(file).readlines()
    length = len(word_list)
    i = 1
    for line in word_list:
        remaining = length - i
        p = line.strip()
        out_file_name = 'out_%s_key.txt' % file_name
        cmd = "steghide extract -sf %s -p %s -xf %s" % (file_name, p, out_file_name)
        r = run_shell_cmd(cmd)

        if r != '' and 'Syntax error:' not in r and "could not extract" not in r:
            print("FOUND!!!!!!=> " + line)
            print('password: %s' % r)
            break
        else:
            print("Remaining : %s" % remaining)

        i += 1


if __name__ == '__main__':
    main()
