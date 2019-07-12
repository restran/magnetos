# magnetos

[![travis-ci](https://travis-ci.org/restran/magnetos.svg?branch=master)](https://travis-ci.org/restran/magnetos) [![Coverage Status](https://coveralls.io/repos/github/restran/magnetos/badge.svg?branch=master)](https://coveralls.io/github/restran/magnetos?branch=master) [![pypi package](https://img.shields.io/pypi/v/magnetos.svg)](https://pypi.python.org/pypi/magnetos/)

一款帮你在 CTF 比赛中加速解题的工具

<div style="max-width: 270px; margin: 0 auto; ">
<img src="docs/icon/magnetos.png" style="margin: 0 auto; max-width: 270px; display: block;">
</div>



## 依赖的第三方工具

- [zsteg](https://github.com/zed-0xff/zsteg)
- pngcheck
- [stegdetect](https://github.com/abeluck/stegdetect) 
- exiftool

```
apt install pngcheck
apt install libimage-exiftool-perl
gem install zsteg
wget http://launchpadlibrarian.net/16746333/stegdetect_0.6-6_amd64.deb
dpkg -i stegdetect_0.6-6_amd64.deb
```

## 安装方法

    pip3 install magnetos

## 提供的工具

以下工具可以在命令行下直接执行

- what_format，类似 binwalk 和 foremost，但可以分离出一些其他文件，例如 psd
- what_code_scheme，检测编码类型
- what_encode，自动检测文件编码并进行模糊测试
- what_steg，隐写题目自动化解题工具
- web_get，自动下载指定 URL 的所有资源到本地
- file_hash，计算文件 hash
- file_strings，与 strings 命令相同，但是会自动过滤掉\0
- find_ctf_flag，根据 flag 特征从文本文件或目录中查找可能的 flag
- reverse_proxy，反向代理
- steg_hide_cracker，爆破 steghide 密码
