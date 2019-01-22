# -*- coding: utf-8 -*-
# Created by restran on 2017/11/9
from __future__ import unicode_literals, absolute_import

import os
import re
import string
import traceback
from optparse import OptionParser
from functools import cmp_to_key
from mountains.encoding import force_text

from ..utils.file_strings import bytes_2_printable_strings

parser = OptionParser()
parser.add_option("-f", "--file name", dest="file_name", type="string",
                  help="read from file")
parser.add_option("-s", "--strict mode", dest="strict_mode",
                  default=False, action="store_true",
                  help="use strict mode, only exists ctf, flag, key")


def get_flag_from_file(file_path, strict_mode=False, result_dict=None):
    if not os.path.exists(file_path):
        if result_dict is not None:
            result = '\n'.join(result_dict.keys())
        else:
            result = ''
        return result

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
        (r'(?:key|flag|ctf|synt|galf)[\x20-\x7E]{5,41}', re.I),
        # (r'(?:key|flag|ctf|synt|galf)[\x20-\x7E]{0,3}(?::|=|\{|is)[\x20-\x7E]{,40}', re.I),
        (r'k.{0,2}e.{0,2}y[\x20-\x7E]{0,2}(?::|=|\{|is)[\x20-\x7E]{3,40}', re.I),
        (r'f.{0,2}l.{0,2}a.{0,2}g[\x20-\x7E]{0,2}(?::|=|\{|is)[\x20-\x7E]{3,40}', re.I),
        (r'c.{0,2}t.{0,2}f.{0,2}[\x20-\x7E]{0,2}(?::|=|\{|is)[\x20-\x7E]{3,40}', re.I),
        (r's.{0,2}y.{0,2}n.{0,2}t[\x20-\x7E]{0,2}(?::|=|\{|is)[\x20-\x7E]{3,40}', re.I),
        (r'g.{0,2}a.{0,2}l.{0,2}f[\x20-\x7E]{0,2}(?::|=|\{|is)[\x20-\x7E]{3,40}', re.I),
    ]

    if not strict_mode:
        re_list.extend([
            (r'[a-z0-9]{0,8}[\x20-\x7E]{0,3}\{[\x20-\x7E]{4,40}\}', re.I),
            (r'[\x20-\x7E]{0,8}[a-zA-Z0-9_]{16}[\x20-\x7E]{0,5}', re.I),
            (r'[\x20-\x7E]{0,8}[a-zA-Z0-9_]{32}[\x20-\x7E]{0,5}', re.I),
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


def clean_find_ctf_flag_result(result):
    def re_match_flag(a):
        re_list = [
            (r'(key|flag|ctf|synt|galf)[\x20-\x7E]{5,41}', re.I),
            (r'[\x20-\x7E]{5,41}(yek|ftc|galf|tnys)', re.I),
            (r'k[\x20-\x7E]?e[\x20-\x7E]?y[\x20-\x7E]?(\s|:|=|\{|is)[\x20-\x7E]{3,40}', re.I),
            (r'f[^\w]?l[\x20-\x7E]?a[\x20-\x7E]?g[\x20-\x7E]?(\s|:|=|\{|is)[\x20-\x7E]{3,40}', re.I),
            (r'c[\x20-\x7E]?t[\x20-\x7E]?f[\x20-\x7E]?(\s|:|=|\{|is)[\x20-\x7E]{3,40}', re.I),
            (r's[\x20-\x7E]?y[\x20-\x7E]?n[\x20-\x7E]?t[\x20-\x7E]?(\s|:|=|\{|is)[\x20-\x7E]{3,40}', re.I),
            (r'g[\x20-\x7E]?a[\x20-\x7E]?l[\x20-\x7E]?f[\x20-\x7E]?(\s|:|=|\{|is)[\x20-\x7E]{3,40}', re.I),
        ]

        pattern_list = [re.compile(*r) for r in re_list]
        for p in pattern_list:
            r = p.search(a)
            if r:
                return True
        else:
            return False

    def re_match_flag_2(a):
        re_list = [
            (r'(key|flag|ctf|synt|galf)(\s|:|=|\{|is)[\x20-\x7E]{5,40}', re.I),
            (r'[\x20-\x7E]{5,40}(\s|:|=|\{|is)(yek|ftc|galf|tnys)', re.I),
        ]

        pattern_list = [re.compile(*r) for r in re_list]
        for p in pattern_list:
            r = p.search(a)
            if r:
                return True
        else:
            return False

    def math_flag_bracket(a):
        count = 0
        if '{' in a:
            count += 1
        if '}' in a:
            count += 1

        return count

    def sort_result(a, b):
        found_a = re_match_flag(a)
        found_b = re_match_flag(b)

        if found_a and not found_b:
            return 1
        elif not found_a and found_b:
            return -1
        else:
            # 使用更精确的flag特征判断
            found_a = re_match_flag_2(a)
            found_b = re_match_flag_2(b)
            if found_a and not found_b:
                return 1
            elif not found_a and found_b:
                return -1
            else:
                # 如果有括号，则准确度更高
                count_a_bracket = math_flag_bracket(a)
                count_b_bracket = math_flag_bracket(b)
                if count_a_bracket > count_b_bracket:
                    return 1
                elif count_a_bracket < count_b_bracket:
                    return -1

            return 0

    result_list = result.splitlines()
    return sorted(result_list, key=cmp_to_key(sort_result), reverse=True)


def main():
    (options, args) = parser.parse_args()

    if options.file_name is not None:
        file_name = options.file_name
    elif len(args) > 0:
        file_name = args[0]
    else:
        parser.print_help()
        return

    if not os.path.exists(file_name):
        return

    if os.path.isfile(file_name):
        result = get_flag_from_file(file_name, options.strict_mode)
        result_list = clean_find_ctf_flag_result(result)
        print('\n'.join(result_list))
    elif os.path.isdir(file_name):
        for root, dirs, files in os.walk(file_name):
            for f in files:
                f_name = os.path.join(root, f)
                print('\n---------------------')
                print('file: %s' % f_name)
                result = get_flag_from_file(f_name, options.strict_mode)
                print(result)


if __name__ == '__main__':
    main()
