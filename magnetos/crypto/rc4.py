# -*- coding: utf-8 -*-
# Created by restran on 2016/12/4
# https://github.com/RyanKung/rc4-python3/blob/master/rc4/rc4.py

__all__ = ['encrypt', 'decrypt', 'encrypt_json', 'decrypt_json']


def crypt(data: bytes, key: bytes) -> bytes:
    """RC4 algorithm"""
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + int(box[i]) + int(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]

    print(len(data))
    x = y = 0
    out = []

    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        t = char ^ box[(box[x] + box[y]) % 256]

        out.append(t)

    return bytes(bytearray(out))


def encrypt(data: str, key: str) -> bytes:
    """RC4 encryption with random salt and final encoding"""
    data = crypt(data.encode(), key.encode())
    return data


def decrypt(data: bytes, key: str) -> bytes:
    """RC4 decryption of encoded data"""
    return crypt(data, key.encode())


def main():
    # 需要加密的数据
    data = 'UUyFTj8PCzF6geFn6xgBOYSvVTrbpNU4OF9db9wMcPD1yDbaJw=='
    # 密钥
    key = 'welcometoicqedu'

    # 加码
    encoded_data = encrypt(data=data, key=key)
    print(encoded_data)
    # 解码
    decoded_data = decrypt(data=encoded_data, key=key)
    print(decoded_data)


if __name__ == '__main__':
    main()
