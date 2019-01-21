# magnetos

[![travis-ci](https://travis-ci.org/restran/magnetos.svg?branch=master)](https://travis-ci.org/restran/magnetos)
[![Coverage Status](https://coveralls.io/repos/github/restran/magnetos/badge.svg?branch=master)](https://coveralls.io/github/restran/magnetos?branch=master)

Toolkit for security scripts developing.

## 依赖的第三方工具

- zsteg
- pngcheck
- [stegdetect](https://github.com/abeluck/stegdetect) 
- exiftool

```
apt install pngcheck
apt install libimage-exiftool-perl
gem install zsteg
dpkg -i stegdetect_0.6-6_amd64
```

## 安装方法

    pip3 install magnetos

## 提供的工具

以下工具可以在命令下直接执行

- what_format
- what_code_scheme
- what_encode
- what_steg CTF隐写自动化解题工具
- file_hash
- file_strings
- find_ctf_flag
- reverse_proxy
- steg_hide_break
