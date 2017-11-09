# -*- coding: utf-8 -*-
# Created by restran on 2017/11/9
from __future__ import unicode_literals, absolute_import

from optparse import OptionParser
from mountains.encoding import force_bytes
from mountains import PY2

parser = OptionParser()
parser.add_option("-f", "--file name", dest="file_name", type="string",
                  help="read from file")


def bytes_2_printable_strings(data):
    data = force_bytes(data)
    result = ['', '']
    for c in data:
        if PY2:
            c = ord(c)

        if 32 <= c <= 126 or c in (9, 10, 13):
            if c == 9:
                c = 32
            elif c == 13:
                c = 10

            # 去掉连续的空格
            if c == 32 and result[-1] == ' ':
                continue
            # 去掉连续的换行
            elif c == 10 and result[-1] == '\n':
                continue

            result.append(chr(c))

    return ''.join(result)


def file_2_printable_strings(file_name, output_file=None, print_output=False):
    with open(file_name, 'rb') as f:
        data = f.read()

    data = bytes_2_printable_strings(data)

    if output_file is not None:
        with open(output_file, 'w') as f:
            f.write(data)

    if print_output:
        print(data)

    return data


def main():
    (options, args) = parser.parse_args()

    if options.file_name is not None:
        file_name = options.file_name
    elif len(args) > 0:
        file_name = args[0]
    else:
        parser.print_help()
        return

    result = file_2_printable_strings(file_name, print_output=True)
    print(result)


if __name__ == '__main__':
    main()
