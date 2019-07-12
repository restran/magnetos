# -*- coding: utf-8 -*-
# Created by restran on 2017/7/30
from __future__ import unicode_literals, absolute_import

import binascii
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import zipfile
from optparse import OptionParser

from PIL import Image
from mountains import force_text, force_bytes
from mountains import logging
from mountains.file import write_bytes_file
from mountains.logging import ColorStreamHandler, FileHandler

from ..utils import find_ctf_flag, file_strings
from ..utils.converter import partial_base64_decode, hex2str, bin2str

parser = OptionParser()
parser.add_option("-f", "--file_name", dest="file_name", type="string",
                  help="read from file")
parser.add_option("-s", "--flag_strict_mode", dest="flag_strict_mode", default=False,
                  action="store_true", help="find flag strict mode")

"""
依赖 pngcheck、zsteg、stegdetect

自动检测文件可能的隐写，需要在Linux下使用 Python3 运行
一些依赖还需要手动安装
TODO:
FFD9 后的文件内容显示出来
"""

logging.init_log(ColorStreamHandler(logging.INFO, '%(message)s'),
                 FileHandler(level=logging.INFO))

logger = logging.getLogger(__name__)


class WhatSteg(object):
    def __init__(self, file_path, flag_strict_mode=True):
        self.file_path = file_path
        self.current_path = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)
        # 文件的扩展名
        self.file_ext = (os.path.splitext(base_name)[1]).lower()

        # 文件类型
        self.file_type = ''

        self.output_path = os.path.join(self.current_path, 'output_%s' % base_name)
        self.flag_strict_mode = flag_strict_mode
        # 需要强调输出的结果内容
        self.result_list = []

        self.extract_file_md5_dict = {}
        self.log_file_name = 'log.txt'
        self.file_img_size = None
        # 是否要跳过 zsteg 的处理，当bmp的图片高度被修改过，zsteg会卡住
        self.skip_zsteg = False

        # 删除旧的数据
        self.remove_dir(self.output_path)
        # 创建输出路径
        if not os.path.exists(self.output_path):
            os.mkdir(self.output_path)

        logging.init_log(ColorStreamHandler(logging.INFO, '%(message)s'),
                         FileHandler(filename=os.path.join(self.output_path, self.log_file_name),
                                     format='%(message)s', level=logging.DEBUG))

    def run_shell_cmd(self, cmd):
        try:
            (stdout, stderr) = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE, shell=True,
                                                universal_newlines=True).communicate()
            if stdout is None:
                stdout = ''
            if stderr is None:
                stderr = ''
            return '%s%s' % (stdout, stderr)
        except Exception as e:
            logger.error(e)
            logger.error(cmd)
            return ''

    def strings(self):
        logger.info('\n--------------------')
        logger.info('run strings')
        out_file = os.path.join(self.output_path, 'strings_1.txt')
        cmd = 'strings %s > %s' % (self.file_path, out_file)
        self.run_shell_cmd(cmd)
        out_file = os.path.join(self.output_path, 'strings_2.txt')
        file_strings.file_2_printable_strings(self.file_path, out_file)

    def check_strings(self):
        file_path = os.path.join(self.output_path, 'strings_1.txt')
        with open(file_path, 'r') as f:
            string_data = f.read()

        if 'Adobe Fireworks' in string_data and self.file_type == 'png':
            self.result_list.append('[*] 很可能是 Fireworks 文件，请用 Fireworks 打开')
        if 'Adobe Photoshop' in string_data:
            self.result_list.append('[*] 可能存在 Photoshop 的 psd 文件，请检查是否有分离出 psd 文件')

    def png_check(self):
        if self.file_type == 'png':
            logger.info('\n--------------------')
            logger.info('run pngcheck')
            cmd = 'pngcheck -vv %s' % self.file_path
            stdout = self.run_shell_cmd(cmd)
            logger.info(stdout)
            if 'CRC error' in stdout:
                self.result_list.append('[*] PNG 文件 CRC 错误，请检查图片的大小是否有被修改')
                pattern = r'\(computed\s([0-9a-zA-Z]{8})\,\sexpected\s([0-9a-zA-Z]{8})\)'
                keywords = ['flag', 'synt']
                for line in stdout.splitlines():
                    r = re.search(pattern, line)
                    if not r:
                        continue

                    for t in r.groups():
                        try:
                            x = hex2str(t)
                            if x.lower() in keywords:
                                logger.warning('检测到 flag 特征数据，{} -> {}'.format(t, x))
                        except:
                            pass

            out_list = stdout.split('\n')
            last_length = None
            for t in out_list:
                t = t.strip()
                t = force_text(t)
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

    def gif_check(self):
        if self.file_ext == 'gif':
            cmd = 'identify -format "%s %T \\n" {}'.format(self.file_path)
            try:
                output = self.run_shell_cmd(cmd)
                lines = output.splitlines()
                lines = [t.split(' ')[1] for t in lines]
                set_lines = set(lines)
                if 2 <= len(set_lines) <= 100:
                    logger.warning('GIF 帧间隔可能存在隐写')
                    logger.warning(' '.join(lines))
                    # 猜测可能是01的布尔型数据
                    if len(set_lines) == 3:
                        for i, t in enumerate(lines):
                            if t != lines[0]:
                                new_lines = ['0' if x == t else '1' for x in lines[i:]]
                                result = bin2str(''.join(new_lines))
                                logger.warning(result)
                                break
                    elif len(set_lines) == 2:
                        new_lines = ['0' if x == lines[0] else '1' for x in lines]
                        result = bin2str(''.join(new_lines))
                        logger.warning(result)

            except:
                pass

    def img_height_check(self):
        """
        检测文件高度被修改过
        如果是修改宽度，会导致图片偏移而显示混乱
        windows忽略crc32检验码，png 可以直接修改任意高度，linux 会校验crc32，导致无法打开
        bmp 修改太高会导致文件打不开
        :return:
        """
        if self.file_type not in ('png', 'bmp', 'jpg'):
            return

        with open(self.file_path, 'rb') as f:
            data = f.read()

        w, h = self.file_img_size

        if self.file_type == 'png':
            bytes_data = data[12:33]
            crc32 = bytes_data[-4:]
            crc32 = struct.unpack('>i', crc32)[0]

            new_h = h * 2
            if binascii.crc32(bytes_data[:-4]) & 0xffffffff != crc32:
                logger.warning('[*] PNG图片宽高CRC32校验失败，文件宽高被修改过')
                logger.warning('[*] 尝试爆破图片高度')
                new_h = h * 2
                for i in range(1, 65535):
                    height = struct.pack('>i', i)
                    check_data = bytes_data[:8] + height + bytes_data[-9:-4]
                    crc32_result = binascii.crc32(check_data) & 0xffffffff
                    if crc32_result == crc32:
                        logger.warning('[*] 找到正确的图片高度: %s' % i)
                        new_h = i
                        break
                else:
                    # linux 下，如果 png 图片高度改得太大，会无法打开，windows 下可以打开
                    logger.warning('[*] 未找到正确的图片高度，自动修改为2倍，请在Windows下打开')

            for x in range(4):
                height = struct.pack('>i', new_h)
                data = bytearray(data)
                data[20 + x] = height[x]
                data = bytes(data)

            logger.warning('[*] 保存修正高度后的文件: fix_height.png')
            out_path = os.path.join(self.output_path, 'fix_height.png')
            write_bytes_file(out_path, data)

        elif self.file_type == 'jpg':
            # im = Image.open(self.file_path)
            # # 获得图像尺寸:
            # w, h = im.size
            # print(w, h)
            x_img = struct.pack('>h', w)
            y_img = struct.pack('>h', h)
            begin = 0
            while True:
                x = data.find(y_img + x_img, begin)
                if x <= 0:
                    break

                bytes_data = data[x - 5:x + 5]
                sz_section = struct.unpack('>h', bytes_data[2:4])[0]
                nr_comp = struct.unpack('>b', bytes_data[-1:])[0]
                if sz_section - 8 != nr_comp * 3:
                    begin = x
                else:
                    # jpg可以任意增加高度，不会影响显示，图片高度增加为2倍
                    new_height = struct.pack('>h', int(h * 2))
                    for y_i in range(2):
                        data = bytearray(data)
                        data[x + y_i] = new_height[y_i]
                        data = bytes(data)

                    logger.warning('[*] 保存扩展高度后的文件: enlarge_height.jpg')
                    out_path = os.path.join(self.output_path, 'enlarge_height.jpg')
                    write_bytes_file(out_path, data)
                    break
        elif self.file_type == 'bmp':
            file_size = os.path.getsize(self.file_path)
            bit_count = data[28:30]
            # 1个像素占用多少字节，这个值一般是24或者32，bmp 图片使用小端序
            bit_count = struct.unpack('<h', bit_count)[0]
            if bit_count not in (24, 32):
                logger.warning('[*] 异常的 bmp bit count %s' % bit_count)
            real_height = int((file_size - 54) / (bit_count / 8) / w)

            if h != real_height:
                logger.warning('[*] 图片高度不正确，或者图片末尾附加了数据')
                logger.warning('[*] 正确的高度为: %s' % real_height)
                # bmp 图片使用小端序
                y_img = struct.pack('<i', real_height)
                for x in range(4):
                    data = bytearray(data)
                    data[22 + x] = y_img[x]
                    data = bytes(data)

                logger.warning('[*] 保存修正高度后的文件: fix_height.bmp')
                out_path = os.path.join(self.output_path, 'fix_height.bmp')
                logger.warning('[*] bmp的高度被修改，运行zsteg可能会耗时很久，已跳过')
                self.skip_zsteg = True
                write_bytes_file(out_path, data)

    def check_file(self):
        logger.info('--------------------')
        logger.info('run file')
        cmd = 'file %s' % self.file_path
        stdout = self.run_shell_cmd(cmd)
        if 'PNG image data' in stdout:
            self.file_type = 'png'
        elif 'JPEG image data' in stdout:
            self.file_type = 'jpg'
        elif 'bitmap' in stdout:
            self.file_type = 'bmp'
        else:
            self.file_type = os.path.splitext(self.file_path)[1].lstrip('.')

        if self.file_type in ('png', 'jpg', 'bmp'):
            try:
                im = Image.open(self.file_path)
                # 获得图像尺寸
                # w, h
                self.file_img_size = im.size
            except:
                self.file_img_size = None

        self.file_type = self.file_type.lower()
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
        if self.file_type not in ['bmp', 'png']:
            return

        if self.skip_zsteg:
            return

        logger.info('\n--------------------')
        logger.info('run zsteg')
        out_file = os.path.join(self.output_path, 'zsteg.txt')
        cmd = 'zsteg -a -v %s > %s' % (self.file_path, out_file)
        self.run_shell_cmd(cmd)

        file_list = [
            ['PC bitmap, Windows', 'bmp'],
            ['PNG image data', 'png'],
            ['JPEG image data', 'jpg'],
            ['GIF image data', 'gif'],
            ['Zip archive data', 'zip'],
            ['RAR archive data', 'rar'],
            ['gzip compressed data', 'gz'],
            ['7-zip archive data', '7z'],
            ['PDF document', 'pdf'],
            ['Python script', 'py'],
            ['python ', 'pyc'],
            ['tcpdump capture file', 'pcap'],
            ['pcap-ng capture file', 'pcapng'],
            ['PE32 executable ', 'exe'],
            ['PE64 executable ', 'exe'],
            ['ELF ', 'elf'],
        ]

        file_list = [[' file: %s' % t[0], t[1]] for t in file_list]
        # 自动检测 zsteg 隐写是否有检测到隐藏文件
        line_count = 0
        out_path = os.path.join(self.output_path, 'zsteg')
        if not os.path.exists(out_path):
            os.makedirs(out_path)

        zsteg_text_dict = {}

        with open(out_file, 'r') as f:
            for line in f:
                line = line.strip()
                line_count += 1
                for i, t in enumerate(file_list):
                    # 记录所有的 text 数据
                    if '.. text: "' in line and line.endswith('"'):
                        md5 = hashlib.md5(force_bytes(line)).hexdigest()
                        if md5 not in zsteg_text_dict:
                            zsteg_text_dict[md5] = line

                        # 凭经验设置的一个大概的值，zsteg 日志没有将所有的文本输出
                        # 如果输出的内容比较长的情况下，就要考虑将文本文件提取出来
                        if len(line) <= 120:
                            break
                        else:
                            index = line.find('.. text: "')
                            zsteg_payload = line[:index].rstrip(' .').strip()
                            extract_file_ext = 'txt'
                            extract_file_type = 'txt'
                    else:
                        if t[0] not in line:
                            continue
                        else:
                            index = line.find(t[0])
                            zsteg_payload = line[:index].rstrip(' .').strip()
                            extract_file_ext = t[1]
                            extract_file_type = t[0][len(' file: '):]

                    # 检测到文件后，自动导出文件
                    if len(zsteg_payload.split(',')) > 0:
                        f_name = '%s_%s.%s' % (line_count, i, extract_file_ext)
                        out_file_path = os.path.join(out_path, f_name)
                        cmd = "zsteg %s -E '%s' > %s" % (
                            self.file_path, zsteg_payload, out_file_path)
                        logger.warning('[*] zsteg 检测到文件 %s' % line.strip())
                        self.run_shell_cmd(cmd)

                    msg = '[*] zsteg日志第%d行检测到文件%s' % (
                        line_count, extract_file_type)
                    self.result_list.append(msg)
                    break

        text_out_file = os.path.join(self.output_path, 'zsteg_text.txt')
        with open(text_out_file, 'w') as f:
            for line in zsteg_text_dict.values():
                f.write(line)
                f.write('\n')

                # 自动解码 base64 文本
                text = line[line.index('.. text: "') + len('.. text: "'):-1]
                b64rex = re.compile('^[A-Za-z0-9+/=]{4,}$')
                if b64rex.match(text):
                    text = file_strings.bytes_2_printable_strings(partial_base64_decode(text))
                    if len(text) > 5:
                        f.write('[base64_decode]: {}\n'.format(text))

    def stegdetect(self):
        """
        用于检测 jpg 的隐写
        :return:
        """
        if self.file_type == 'jpg':
            logger.info('\n--------------------')
            logger.info('run stegdetect')
            # -s 表示敏感度，太低了会检测不出来，太大了会误报
            cmd = 'stegdetect -s 5 %s' % self.file_path
            stdout = self.run_shell_cmd(cmd)
            logger.info(stdout)
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
                text = '[*] 使用了 jphide 隐写，如果没有提供密码，可以先用 Jphswin.exe 试一下空密码，再用 stegbreak 用弱口令爆破'
                self.result_list.append(text)
                text = '[*] 也有可能是 steghide 隐写，如果没有提供密码，可以用 steg_hide_break 用弱口令爆破'
                self.result_list.append(text)
                text = '[*] 也有可能是 outguess 隐写，outguess -r in.jpg out.txt'
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
                        logger.info('压缩包 %s 需要密码' % tmp_file_path)
                    else:
                        logger.info('压缩包 %s 解压失败' % tmp_file_path)
                    return False
        except Exception as e:
            logger.info('压缩包 %s 解压失败' % tmp_file_path)
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
            'strings_1.txt',
            'strings_2.txt',
            'zsteg.txt',
            'zsteg_text.txt',
            'log.txt',
            'enlarge_height.{}'.format(self.file_type),
            'fix_height.{}'.format(self.file_type)
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

                # 删除大小为空的文件
                file_size = os.path.getsize(path)
                if file_size <= 0:
                    os.remove(path)
                    continue

                md5 = self.check_file_md5(path)
                file_ext = os.path.splitext(path)[1].lower()
                if file_ext != '':
                    # 去掉前面的.
                    file_ext = file_ext[1:]

                if md5 in self.extract_file_md5_dict:
                    old_file = self.extract_file_md5_dict[md5]
                    # 如果是有扩展名的，则替换没有扩展名的
                    if file_ext == '' or old_file['ext'] != '':
                        continue

                self.extract_file_md5_dict[md5] = {
                    'path': path,
                    'ext': file_ext
                }

        for k, v in self.extract_file_md5_dict.items():
            if v['ext'] in file_type_dict:
                item = file_type_dict[v['ext']]
                item.append(v['path'])
            else:
                file_type_dict[v['ext']] = [v['path']]

        total_num = len(self.extract_file_md5_dict.keys())
        self.result_list.append('\n')
        self.result_list.append('[+] 分离出的文件数: %s' % total_num)
        has_zip = False
        # 把所有不重复的文件，按文件类型重新存储
        for file_type, v in file_type_dict.items():
            if file_type == '':
                file_type = 'unknown'

            path = os.path.join(self.output_path, file_type)
            if not os.path.exists(path):
                os.mkdir(path)

            self.result_list.append('[+] %s: %s' % (file_type, len(v)))
            file_name_dict = {}
            for i, f_p in enumerate(v):
                # 默认使用分离文件时的文件名，如果出现冲突，再用数字
                base_name = os.path.basename(f_p)
                if base_name not in file_name_dict:
                    f_name = base_name
                    file_name_dict[f_name] = None
                else:
                    if file_type != 'unknown':
                        f_name = '%s.%s' % (i, file_type)
                    else:
                        f_name = '%s' % i

                p = os.path.join(path, f_name)
                try:
                    # 移动文件
                    shutil.move(f_p, p)
                except Exception as e:
                    logger.error(e)
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
        path = os.path.join(self.output_path, 'zsteg')
        self.remove_dir(path)

        if has_zip:
            self.result_list.append('[!] 如果 zip 文件打开后有很多 xml，很可能是 docx')

    @classmethod
    def remove_dir(cls, dir_path):
        try:
            if os.path.exists(dir_path):
                shutil.rmtree(dir_path, ignore_errors=True)
        except:
            pass

    def binwalk(self):
        logger.info('\n--------------------')
        logger.info('run binwalk')
        out_path = os.path.join(self.output_path, 'binwalk')
        self.remove_dir(out_path)
        # binwalk 会自动对 zlib 文件解压缩，可以进一步对解压缩后的文件类型进行识别
        cmd = 'binwalk -v -M -e -C %s %s' % (out_path, self.file_path)
        stdout = self.run_shell_cmd(cmd)
        # 不要输出那么多
        logger.info('\n'.join(stdout.splitlines()[:20]))
        self.process_binwalk_unknown(out_path)

    def process_binwalk_unknown(self, binwalk_path):
        logger.info('\n--------------------')
        logger.info('process binwalk unknown files')
        for root, dirs, files in os.walk(binwalk_path):
            for f_name in files:
                path = os.path.join(root, f_name)
                file_ext = os.path.splitext(path)[1].lower()
                if file_ext == '':
                    out_path = os.path.join(root, 'out_' + f_name)
                    cmd = 'what_format -f %s -o %s -e bmp -e gif -e pdf' % (path, out_path)
                    stdout = self.run_shell_cmd(cmd)
                    logger.info(out_path)
                    logger.info('\n'.join(stdout.splitlines()[:20]))

    def foremost(self):
        logger.info('\n--------------------')
        logger.info('run foremost')
        out_path = os.path.join(self.output_path, 'foremost')
        self.remove_dir(out_path)
        cmd = 'foremost -o %s %s' % (out_path, self.file_path)
        stdout = self.run_shell_cmd(cmd)
        # 不要输出那么多
        logger.info('\n'.join(stdout.splitlines()[:20]))

    def what_format(self):
        logger.info('\n--------------------')
        logger.info('run what_format')
        out_path = os.path.join(self.output_path, 'what_format')
        self.remove_dir(out_path)
        cmd = 'what_format -f %s -o %s -e bmp -e gif -e pdf' % (self.file_path, out_path)
        stdout = self.run_shell_cmd(cmd)
        # 不要输出那么多
        logger.info('\n'.join(stdout.splitlines()[:30]))

    def run_exif_tool(self):
        if self.file_type not in ['bmp', 'png', 'jpg', 'jpeg', 'gif']:
            return

        logger.info('\n--------------------')
        logger.info('run exiftool')
        # -j 将结果输出为json格式
        cmd = 'exiftool -j %s' % self.file_path
        stdout = self.run_shell_cmd(cmd)

        if self.file_img_size is None:
            try:
                json_data = json.loads(stdout)
                if len(json_data) > 0:
                    json_data = json_data[0]
                self.file_img_size = (json_data['ImageWidth'], json_data['ImageHeight'])
            except:
                pass

        logger.info(stdout)

    def check_abnormal_file_magic(self):
        """
        检查一些异常的文件头，例如将 Rar! 改成 raR!
        :return:
        """
        file_path = os.path.join(self.output_path, 'strings_1.txt')
        with open(file_path, 'r') as f:
            data = f.read()

        magic_dict = {
            'RAR!': 'rar',
            'PK': 'zip',
            'PNG': 'png',
            'JFIF': 'jpg'
        }

        re_list = [
            (r'({})'.format('|'.join(magic_dict)), re.I),
        ]

        result_dict = {}
        for r, option in re_list:
            if option is not None:
                pattern = re.compile(r, option)
            else:
                pattern = re.compile(r)

            ret = pattern.findall(data)
            if len(ret) > 0:
                ret = set([t.upper() for t in ret])
                for t in ret:
                    t = magic_dict.get(t, t)
                    if t not in result_dict:
                        result_dict[t] = None

        file_list = [t.lower() for t in result_dict.keys() if t.lower() != self.file_type]
        if len(file_list) > 0:
            logger.warning('[*] 文件中可能存在（误报率较高，仅参考）： {}'.format(', '.join(file_list)))
            logger.warning('[*] 请检查文件尾是否有附加数据')

    def find_flag(self):
        """
        自动查找可能的 flag
        :return:
        """
        logger.info('\n--------------------')
        logger.info('尝试从文件文本中提取 flag')
        find_flag_result_dict = {}
        # zsteg 日志文件，因为有16进制数据，如果不用严格模式，会有很多误报的数据
        zsteg_file = os.path.join(self.output_path, 'zsteg.txt')
        find_ctf_flag.get_flag_from_file(zsteg_file, True, find_flag_result_dict)
        strings_file = os.path.join(self.output_path, 'strings_1.txt')
        find_ctf_flag.get_flag_from_file(strings_file, self.flag_strict_mode, find_flag_result_dict)
        strings_file = os.path.join(self.output_path, 'strings_2.txt')
        find_ctf_flag.get_flag_from_file(strings_file, self.flag_strict_mode, find_flag_result_dict)
        strings_file = os.path.join(self.output_path, 'zsteg_text.txt')
        find_ctf_flag.get_flag_from_file(strings_file, self.flag_strict_mode, find_flag_result_dict)

        # 自动从分离出的 txt 文件中查找可能的 flag
        txt_dir = os.path.join(self.output_path, 'txt')
        if os.path.exists(txt_dir):
            for root, dirs, files in os.walk(txt_dir):
                for f in files:
                    txt_file_path = os.path.join(root, f)
                    find_ctf_flag.get_flag_from_file(
                        txt_file_path, self.flag_strict_mode, find_flag_result_dict)

        result_list = find_ctf_flag.clean_find_ctf_flag_result('\n'.join(find_flag_result_dict.keys()))
        max_line = 20
        if len(result_list) > max_line:
            logger.info('匹配的内容较多，只显示前%s条，更多数据在日志文件中查看' % max_line)

        for x in result_list[:max_line]:
            logger.warning(x)
        for x in result_list[max_line:]:
            logger.debug(x)

    def run(self):
        self.check_file()
        self.strings()
        self.run_exif_tool()
        self.img_height_check()
        self.zsteg()
        self.binwalk()
        self.foremost()
        self.what_format()
        self.png_check()
        self.gif_check()
        self.stegdetect()
        self.check_strings()
        self.check_extracted_file()
        self.check_abnormal_file_magic()

        logger.info('\n--------------------')
        for t in self.result_list:
            logger.warning(t)

        self.find_flag()

        logger.info('=======================')


def main():
    (options, args) = parser.parse_args()

    if options.file_name is not None:
        file_name = options.file_name
    elif len(args) > 0:
        file_name = args[0]
    else:
        parser.print_help()
        return

    file_path = os.path.join(os.getcwd(), file_name)
    WhatSteg(file_path, options.flag_strict_mode).run()


if __name__ == '__main__':
    main()
