# magnetos

Toolkit for security scripts developing.

## Upload to PyPi

安装最新的 setuptools

    pip install -U pip setuptools twine

生成 wheel 包

    python3 setup.py bdist_wheel --universal upload

生成 tar.gz 包，因为 setup.py 用到了 pypandoc，安装的时候会需要依赖

    python3 setup.py register sdist upload

