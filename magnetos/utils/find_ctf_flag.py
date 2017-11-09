# -*- coding: utf-8 -*-
# Created by restran on 2017/11/9
from __future__ import unicode_literals, absolute_import
import re
import os
from mountains.encoding import force_text
from magnetos.utils.file_strings import bytes_2_printable_strings
import string
import traceback
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-f", "--file name", dest="file_name", type="string",
                  help="read from file")
parser.add_option("-s", "--strict mode", dest="strict_mode",
                  default=False, action="store_true",
                  help="use strict mode, only exists ctf, flag, key ")


def get_flag_from_file(file_path, strict_mode=False, result_dict=None):
    if not os.path.exists(file_path):
        return

    with open(file_path, 'rb') as f:
        data = f.read()

    data = force_text(data)
    if isinstance(data, bytes):
        data = bytes_2_printable_strings(data)

    data = data.replace('\n', '')
    data = data.replace('\r', '')
    data = data.replace('\t', '')
    data = data.replace(' ', '')

    # 这里用 ?: 表示不对该分组编号，也不匹配捕获的文本
    # 这样使用 findall 得到的结果就不会只有()里面的东西
    # [\x20-\x7E] 是可见字符
    re_list = [
        # (r'(?:key|flag|ctf)\{[^\{\}]{3,35}\}', re.I),
        # (r'(?:key|KEY|flag|FLAG|ctf|CTF)+[\x20-\x7E]{3,50}', re.I),
        (r'(?:key|flag|ctf)[\x20-\x7E]{5,40}', re.I),
        (r'(?:key|flag|ctf)[\x20-\x7E]{0,3}(?::|=|\{|is)[\x20-\x7E]{,40}', re.I),
    ]

    if not strict_mode:
        re_list.extend([
            (r'[\x20-\x7E]{0,8}[a-zA-Z0-9]{16}[\x20-\x7E]{0,5}', re.I),
            (r'[\x20-\x7E]{0,8}[a-zA-Z0-9]{32}[\x20-\x7E]{0,5}', re.I),
        ])

    if result_dict is None:
        result_dict = {}

    for r, option in re_list:
        # re.I表示大小写无关
        if option is not None:
            pattern = re.compile(r, option)
        else:
            pattern = re.compile(r)
        ret = pattern.findall(data)
        if len(ret):
            try:
                result = []
                for t in ret:
                    x = [x for x in t if t in string.printable]
                    x = ''.join(x)
                    result.append(x)

                result = [t.replace('\n', '').replace('\r', '').strip() for t in ret]
                for t in result:
                    if t not in result_dict:
                        result_dict[t] = None
            except Exception as e:
                print(e)
                print(traceback.format_exc())

    result = '\n'.join(result_dict.keys())
    return result


def main():
    (options, args) = parser.parse_args()

    if options.file_name is not None:
        file_name = options.file_name
    elif len(args) > 0:
        file_name = args[0]
    else:
        parser.print_help()
        return

    result = get_flag_from_file(file_name, options.strict_mode)
    print(result)


if __name__ == '__main__':
    main()
