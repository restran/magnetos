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
apt install exiftool pngcheck
gem install zsteg
dpkg -i stegdetect_0.6-6_amd64
```


## Upload to PyPi

安装最新的 setuptools

    pip3 install -U pip setuptools twine

生成 wheel 包

    python3 setup.py register bdist_wheel --universal upload

生成 tar.gz 包，因为 setup.py 用到了 pypandoc，安装的时候会需要依赖

    python3 setup.py register sdist upload

## 通过 setup install 安装后删除

    python3 setup.py install --record files.txt
    cat files.txt | xargs rm -rf