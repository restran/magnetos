# -*- coding: utf-8 -*-
# Created by restran on 2017/7/30
from __future__ import unicode_literals, absolute_import

import hashlib
import os
import re
import shutil
import string
import subprocess
import traceback
import zipfile
from optparse import OptionParser
from mountains.encoding import to_unicode
parser = OptionParser()
parser.add_option("-f", "--file name", dest="file_name", type="string",
                  help="read from file")

"""
自动检测文件可能的隐写，需要在Linux下使用 Python3 运行
一些依赖还需要手动安装
"""


class WhatStego(object):
    def __init__(self, file_path):
        self.file_path = file_path
        self.current_path = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)
        # 文件的扩展名
        self.file_ext = os.path.splitext(base_name)[1]

        # 文件类型
        self.file_type = None

        self.output_path = os.path.join(self.current_path, 'output_%s' % base_name)

        # 需要强调输出的结果内容
        self.result_list = []

        self.extract_file_md5_dict = {}
        self.log_file_name = 'log.txt'
        self.log_file = None

    def get_flag_from_string(self, file_path):
        if not os.path.exists(file_path):
            return
        with open(file_path, 'r') as f:
            data = f.read()

        data = to_unicode(data)
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
            (r'(?:key|flag|ctf)[\x20-\x7E]{5,35}', re.I),
            (r'(?:key|flag|ctf)[\x20-\x7E]{0,3}(?::|=|\{|is)[\x20-\x7E]{,35}', re.I)
        ]

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
                    self.log(e)
                    self.log(traceback.format_exc())

        result = '\n'.join(result_dict.keys())
        self.log(result)
        self.log('=======================')

    def run_shell_cmd(self, cmd):
        try:
            (stdout, stderr) = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True,
                                                universal_newlines=True).communicate()
            return stdout
        except Exception as e:
            self.log(e)
            self.log('!!!error!!!')
            self.log(cmd)
            return ''

    def strings(self):
        self.log('\n--------------------')
        self.log('run strings')
        out_file = os.path.join(self.output_path, 'strings.txt')
        cmd = 'strings %s > %s' % (self.file_path, out_file)
        self.run_shell_cmd(cmd)

    def check_strings(self):
        file_path = os.path.join(self.output_path, 'strings.txt')
        with open(file_path, 'r') as f:
            string_data = f.read()

        if 'Adobe Fireworks' in string_data and self.file_type == 'png':
            self.result_list.append('[*] 很可能是 Fireworks 文件，请用 Fireworks 打开')
        if 'Adobe Photoshop' in string_data:
            self.result_list.append('[*] 可能存在 Photoshop 的 psd 文件，请检查是否有分离出 psd 文件')

    def png_check(self):
        if self.file_type == 'png':
            self.log('\n--------------------')
            self.log('run pngcheck')
            cmd = 'pngcheck -vv %s' % self.file_path
            stdout = self.run_shell_cmd(cmd)
            self.log(stdout)
            out_list = stdout.split('\n')
            last_length = None
            for t in out_list:
                t = t.strip()
                t = to_unicode(t)
                if t.startswith('chunk IDAT'):
                    try:
                        length = int(t.split(' ')[-1])
                        if last_length is not None and last_length < length:
                            self.result_list.append('[*] PNG 文件尾部可能附加了数据')
                            break
                        else:
                            last_length = length
                    except:
                        pass

    def log(self, text):
        print(text)
        self.log_file.write(text)
        self.log_file.write('\n')

    def check_file(self):
        self.log('\n--------------------')
        self.log('run file')
        cmd = 'file %s' % self.file_path
        stdout = self.run_shell_cmd(cmd)
        if 'PNG image data' in stdout:
            self.file_type = 'png'
        elif 'JPEG image data' in stdout:
            self.file_type = 'jpg'
        elif 'bitmap' in stdout:
            self.file_type = 'bmp'
        stdout = stdout.replace(self.file_path, '').strip()
        stdout = stdout[2:]
        self.result_list.append('[*] 文件类型: %s' % self.file_type)
        self.result_list.append('[*] 文件类型: %s' % stdout)

        file_size = os.path.getsize(self.file_path) / 1024.0
        self.result_list.append('[*] 文件大小: %.3fKB' % file_size)

    def zsteg(self):
        """
        检测 png 和 bmp 的隐写
        :return:
        """
        if self.file_type in ['bmp', 'png']:
            self.log('\n--------------------')
            self.log('run zsteg')
            out_file = os.path.join(self.output_path, 'zsteg.txt')
            cmd = 'zsteg -a -v %s > %s' % (self.file_path, out_file)
            self.run_shell_cmd(cmd)

    def stegdetect(self):
        """
        用于检测 jpg 的隐写
        :return:
        """
        if self.file_type == 'jpg':
            self.log('\n--------------------')
            self.log('run stegdetect')
            # -s 表示敏感度，太低了会检测不出来，太大了会误报
            cmd = 'stegdetect -s 5 %s' % self.file_path
            stdout = self.run_shell_cmd(cmd)
            self.log(stdout)
            stdout = stdout.lower()
            if 'negative' not in stdout.lower():
                self.result_list.append('\n')

            if 'appended' in stdout:
                text = '[*] 图片后面可能附加了文件，请尝试将 jpg 的文件尾 FFD9 后面的数据组成新的文件'
                self.result_list.append(text)
                text = '    请用 WinHex 打开，搜索 FFD9 并观察后面的数据'
                self.result_list.append(text)
                text = '    若没有分离出文件，很可能需要手动修复文件头'
                self.result_list.append(text)
            if 'jphide' in stdout:
                text = '[*] 使用了 jphide 隐写，如果没有提供密码，可以用 stegbreak 用弱口令爆破'
                self.result_list.append(text)
                text = '    注意，jphide 的检测很可能会出现误报，可以尝试'
                self.result_list.append(text)
            if 'outguess' in stdout:
                text = '[*] 使用了 outguess 隐写'
                self.result_list.append(text)
            if 'f5' in stdout:
                text = '[*] 使用了 F5 隐写'
                self.result_list.append(text)
            if 'jsteg' in stdout:
                text = '[*] 使用了 jsteg  隐写'
                self.result_list.append(text)
            if 'invisible secrets' in stdout:
                text = '[*] 使用了 invisible secrets 隐写'
                self.result_list.append(text)

    @classmethod
    def check_file_md5(cls, file_path):
        with open(file_path, 'rb') as f:
            md5 = hashlib.md5(f.read()).hexdigest()
            return md5

    def unzip(self, file_path, destination_path):
        tmp_file_path = file_path.replace(self.current_path, '')
        try:
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                try:
                    zip_ref.extractall(destination_path)
                    return True
                except Exception as e:
                    if 'password required' in e:
                        self.log('压缩包 %s 需要密码' % tmp_file_path)
                    else:
                        self.log('压缩包 %s 解压失败' % tmp_file_path)
                    return False
        except Exception as e:
            self.log('压缩包 %s 解压失败' % tmp_file_path)
            return False

    def unzip_archive(self):
        for root, dirs, files in os.walk(self.output_path):
            for f_name in files:
                path = os.path.join(root, f_name)
                if path.endswith('.zip'):
                    zip_path = path + '_unzip'
                    self.unzip(path, zip_path)

    def check_extracted_file(self):
        # 排除这些文件
        exclude_file_list = [
            'foremost/audit.txt',
            'strings.txt',
            'zsteg.txt',
            'log.txt'
        ]
        exclude_file_list = [
            os.path.join(self.output_path, t)
            for t in exclude_file_list
        ]
        self.extract_file_md5_dict = {}
        file_type_dict = {}

        # 解压出压缩包
        self.unzip_archive()

        for root, dirs, files in os.walk(self.output_path):
            for f_name in files:
                path = os.path.join(root, f_name)
                if path in exclude_file_list:
                    continue

                md5 = self.check_file_md5(path)
                if md5 in self.extract_file_md5_dict:
                    continue

                self.extract_file_md5_dict[md5] = path
                file_ext = os.path.splitext(path)[1].lower()
                if file_ext == '':
                    file_ext = 'unknown'
                else:
                    # 去掉前面的.
                    file_ext = file_ext[1:]

                if file_ext in file_type_dict:
                    item = file_type_dict[file_ext]
                    item.append(path)
                else:
                    file_type_dict[file_ext] = [path]
        total_num = len(self.extract_file_md5_dict.keys())
        self.result_list.append('\n')
        self.result_list.append('[+] 分离出的文件数: %s' % total_num)
        has_zip = False
        # 把所有不重复的文件，按文件类型重新存储
        for file_type, v in file_type_dict.items():
            path = os.path.join(self.output_path, file_type)
            if not os.path.exists(path):
                os.mkdir(path)

            self.result_list.append('[+] %s: %s' % (file_type, len(v)))
            for i, f_p in enumerate(v):
                if file_type != 'unknown':
                    f_name = '%s.%s' % (i, file_type)
                else:
                    f_name = '%s' % i

                p = os.path.join(path, f_name)
                # 移动文件
                shutil.move(f_p, p)
                file_size = os.path.getsize(p) / 1024.0
                self.result_list.append('    %s: %.3fKB' % (i, file_size))

            if file_type == 'zip':
                has_zip = True

        # 自动删除这些文件夹
        path = os.path.join(self.output_path, 'foremost')
        self.remove_dir(path)
        path = os.path.join(self.output_path, 'what_format')
        self.remove_dir(path)
        path = os.path.join(self.output_path, 'binwalk')
        self.remove_dir(path)

        if has_zip:
            self.result_list.append('[!] 如果 zip 文件打开后有很多 xml，很可能是 docx')

    @classmethod
    def remove_dir(cls, dir_path):
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)

    def binwalk(self):
        self.log('\n--------------------')
        self.log('run binwalk')
        out_path = os.path.join(self.output_path, 'binwalk')
        self.remove_dir(out_path)

        cmd = 'binwalk -v -M -e -C %s %s' % (out_path, self.file_path)
        stdout = self.run_shell_cmd(cmd)
        self.log(stdout)

    def foremost(self):
        self.log('\n--------------------')
        self.log('run foremost')
        out_path = os.path.join(self.output_path, 'foremost')
        self.remove_dir(out_path)
        cmd = 'foremost -o %s %s' % (out_path, self.file_path)
        stdout = self.run_shell_cmd(cmd)
        self.log(stdout)

    def what_format(self):
        self.log('\n--------------------')
        self.log('run what_format')
        out_path = os.path.join(self.output_path, 'what_format')
        self.remove_dir(out_path)
        cmd = 'python what_format.py %s %s' % (self.file_path, out_path)
        stdout = self.run_shell_cmd(cmd)
        self.log(stdout)

    def run(self):
        # 删除旧的数据
        self.remove_dir(self.output_path)
        # 创建输出路径
        if not os.path.exists(self.output_path):
            os.mkdir(self.output_path)

        log_file = os.path.join(self.output_path, self.log_file_name)
        self.log_file = open(log_file, 'w')

        self.check_file()
        self.strings()
        self.zsteg()
        self.binwalk()
        self.foremost()
        self.what_format()
        self.png_check()
        self.stegdetect()
        self.check_strings()
        self.check_extracted_file()

        self.log('\n--------------------')
        for t in self.result_list:
            self.log(t)

        self.log('\n--------------------')
        self.log('尝试从文件文本中提取 flag')
        zsteg_txt = os.path.join(self.output_path, 'zsteg.txt')
        self.get_flag_from_string(zsteg_txt)
        strings_txt = os.path.join(self.output_path, 'strings.txt')
        self.get_flag_from_string(strings_txt)

        self.log_file.close()


def main():
    (options, args) = parser.parse_args()

    if options.file_name is not None:
        file_path = os.path.join(os.getcwd(), options.file_name)
        WhatStego(file_path).run()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
