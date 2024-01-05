#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/4 22:05
# @Author  : Peng1013
# 依赖Crypto类库
# pip install pycryptodome #  python3 安装Crypto
# API说明
# encrypt_msg 用于回调处理成功后 生成数据加密后的字典
# decrypt_msg 用于解密从钉钉接收到的回调消息

import base64
import hashlib
import string
import struct
from time import time
from random import choice

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class DingtalkCallbackError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'错误信息: {self.message}'

    def __repr__(self):
        return f'{self.__class__.__name__}({self.message})'


class VerificationError(DingtalkCallbackError):
    def __init__(self, message='验证错误'):
        super().__init__(message)


class DingtalkCallbackCrypto:
    def __init__(self, aes_key, token, app_key):
        self.encoded_aes_key = aes_key
        self.aes_key = base64.decodebytes((self.encoded_aes_key + '=').encode())
        self.iv = self.aes_key[:16]
        self.token = token
        self.app_key = app_key
        self.pad_size = 32

    def aes_decrypt(self, _data: bytes) -> bytes:
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.iv)
        return unpad(cipher.decrypt(_data), self.pad_size)

    def aes_encrypt(self, _data: bytes) -> bytes:
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.iv)
        return cipher.encrypt(pad(_data, self.pad_size))

    def generate_signature(self, nonce: str, timestamp: str, msg_encrypt: str):
        sign_str = ''.join(sorted([nonce, timestamp, self.token, msg_encrypt]))
        return hashlib.sha1(sign_str.encode()).hexdigest()

    def decrypt_msg(self, msg_signature: str, timestamp: str, nonce: str, encrypted_msg: str) -> str:
        sign = self.generate_signature(nonce, timestamp, encrypted_msg)
        if msg_signature != sign:
            raise VerificationError('签名校验错误')
        content = base64.decodebytes(encrypted_msg.encode('UTF-8'))
        decrypted_data = self.aes_decrypt(content)
        msg_len = struct.unpack('>I', decrypted_data[16:20])[0]
        if decrypted_data[(20 + msg_len):].decode() != self.app_key:
            raise VerificationError('appKey校验错误')
        data = decrypted_data[20:(20 + msg_len)].decode()
        return data

    def encrypt_msg(self, msg: str = 'success') -> dict:
        msg_len = struct.pack('>I', len(msg))
        encrypt_str = ''.join([self.generate_random_key(16), msg_len.decode(), msg, self.app_key])
        encrypted_msg = self.aes_encrypt(encrypt_str.encode())
        encrypted_msg = base64.encodebytes(encrypted_msg).decode()
        time_stamp = str(int(time()))
        nonce = self.generate_random_key(16)
        sign = self.generate_signature(nonce, time_stamp, encrypted_msg)
        return {
            'msg_signature': sign,
            'encrypt': encrypted_msg,
            'timeStamp': time_stamp,
            'nonce': nonce
        }

    @staticmethod
    def generate_random_key(size, chars=string.ascii_letters + string.digits):
        return ''.join(choice(chars) for _ in range(size))


if __name__ == '__main__':
    token = "xxxx"
    aes_key = "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus"
    key = "suiteKeyxx"
    dingCrypto = DingtalkCallbackCrypto(aes_key, token, key)
    content = "{xx:11}"
    t = dingCrypto.encrypt_msg(content)
    print(t)
    s = dingCrypto.decrypt_msg(t['msg_signature'], t['timeStamp'], t['nonce'], t['encrypt'])
    print("result:", s)

    test = DingtalkCallbackCrypto("Yue0EfdN5900c1ce5cf6A152c63DDe1808a60c5ecd7", "mryue", "ding6ccabc44d2c8d38b");
    expect = '{"EventType":"check_url"}'
    res = test.encrypt_msg(expect)
    print(res)
    text = test.decrypt_msg("03044561471240d4a14bb09372dfcfd4fd0e40cb", "1608001896814", "WL4PK6yA",
                            '0vJiX6vliEpwG3U45CtXqi+m8PXbQRARJ8p8BbDuD1EMTDf0jKpQ79QS93qEk7XHpP6u+oTTrd15NRPvNvmBKyDCYxxOK+HZeKju4yhELOFchzNukR+t8SB/qk4ROMu3');
    print(text)
    if text == expect:
        print("✅decrypt success")
    else:
        print("❌decrypt failure")
