# -*- coding: utf-8 -*-
# created by restran on 2016/09/30
from __future__ import unicode_literals, absolute_import

import os
import sys
import binascii
import traceback
from mountains.encoding import utf8, to_unicode

# 当前项目所在路径
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
DICT_FILE_NAME = os.path.join(BASE_PATH, 'data/what_format.dic')


def usage():
    data = '''
[+] This script help you to find out the real format of the file or hide data from the file!
[+] the result file save at 'output' dir, go and search it!
[+] http://hi.baidu.com/l34rn
[+] cnh4ckff [at] gmail.com

[+] usage: %s <target file>
    ''' % sys.argv[0].split('\\')[-1]
    print(data)


class WhatFormat(object):
    def __init__(self, file_name, out_path='output'):
        self.file_name = file_name
        self.out_path = out_path
        self.hex_data = ''

    @classmethod
    def load_dict(cls, file_name):
        dict_list = []
        with open(file_name, 'rb') as f:
            for line in f:
                line = to_unicode(line).strip()
                if line != '' and not line.startswith('#'):
                    ext, des, hex_start, hex_end = line.split('::')
                    hex_start = hex_start.lower().replace(' ', '')
                    hex_end = hex_end.lower().replace(' ', '')
                    item = [ext, des, hex_start, hex_end]
                    item = tuple([to_unicode(t.strip()) for t in item])
                    dict_list.append(item)

        return dict_list

    def load_file(self):
        file_name = self.file_name
        size = os.path.getsize(file_name)
        print('''
[+] File:               %s
[+] Size:               %s [Kb]
        ''' % (file_name, str(size / 1024)))
        with open(file_name, 'rb') as f:
            data = f.read()
            hex_data = to_unicode(binascii.hexlify(data))

        self.hex_data = hex_data
        return hex_data

    @classmethod
    def find_all_sub(cls, hex_data, start, match):
        result = []
        tmp_start = start
        while True:
            code = hex_data.find(match, tmp_start)
            if code == -1:
                return result
            else:
                tmp_start = code + len(match)
                result.append(code)

    def check_format(self, hex_data, dict_list):
        res_list = []
        hex_length = len(hex_data)

        for d in dict_list:
            ext, des, hex_start, hex_end = d
            start = 0
            while True:
                code_start = hex_data.find(hex_start, start)
                if code_start != -1:
                    start = code_start + 1
                    if hex_end != '':
                        # 找出所有匹配的文件结尾
                        code_end_list = self.find_all_sub(hex_data, start, hex_end)
                        code_end_list = [t + len(hex_end) for t in code_end_list]
                        if len(code_end_list) >= 0:
                            for code_end in code_end_list:
                                res_list.append((ext, des, code_start, code_end))
                        else:
                            code_end = hex_length
                            res_list.append((ext, des, code_start, code_end))
                    else:
                        code_end = hex_length
                        res_list.append((ext, des, code_start, code_end))
                else:
                    break
        return res_list

    @classmethod
    def extract_data(cls, hex_data, start, end):
        try:
            if end < start:
                return ''

            data = hex_data[start:end]
            if len(data) % 2 != 0:
                data += '0'
            data = binascii.unhexlify(utf8(data))
            return data
        except Exception as e:
            print('extract data error %s' % e)
            return ''

    def output(self, res_list, hex_data):
        i = 0
        for res in res_list:
            i += 1
            ext, des, startup, end = res
            file_name = '%s.%s' % (i, ext)
            data = self.extract_data(hex_data, startup, end)
            if len(data) <= 0:
                continue

            self.save_file(file_name, data)
            print('''
[+] Number:             %s
[+] Extension:          %s
[+] Description:        %s
[+] Startup:            %s
[+] End:                %s
[+] Save as:            %s
            ''' % (i, ext, des, startup, end, file_name))

    def save_file(self, file_name, data):
        if not os.path.exists(self.out_path):
            os.mkdir(self.out_path)

        path = os.path.join(self.out_path, file_name)
        with open(path, 'wb') as f:
            f.write(data)

    def run(self):
        try:
            hex_data = self.load_file()
            dict_list = self.load_dict(DICT_FILE_NAME)
            res_list = self.check_format(hex_data, dict_list)
            self.output(res_list, hex_data)
        except Exception as e:
            print('[!!!] %s' % e)
            print(traceback.format_exc())


def main():
    if len(sys.argv) < 2:
        usage()
        exit()

    file_name = sys.argv[1]
    if len(sys.argv) > 2:
        out_path = sys.argv[2]
    else:
        out_path = 'output'

    WhatFormat(file_name, out_path).run()


if __name__ == '__main__':
    main()
