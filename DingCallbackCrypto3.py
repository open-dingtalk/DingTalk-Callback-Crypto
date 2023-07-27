#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  code copy from https://github.com/shuizhengqi1/DingCrypto/blob/master/DingCrypto.py

# 依赖Crypto类库
# pip install pycryptodome #  python3 安装Crypto
# API说明
# getEncryptedMap 生成回调处理成功后success加密后返回给钉钉的json数据
# decrypt  用于从钉钉接收到回调请求后




import uuid
import struct
import base64
import hashlib
import time
import logging
from Crypto.Cipher import AES

import io,base64, binascii, hashlib, string, struct
from random import choice

from Crypto.Cipher import AES

"""
@param token          钉钉开放平台上，开发者设置的token
@param encodingAesKey 钉钉开放台上，开发者设置的EncodingAESKey
@param corpId         企业自建应用-事件订阅, 使用appKey
                      企业自建应用-注册回调地址, 使用corpId
                      第三方企业应用, 使用suiteKey
"""
class DingCallbackCrypto3:
    def __init__(self, token, encodingAesKey, key):
        self.encodingAesKey = encodingAesKey
        self.key = key
        self.token = token
        self.aesKey = base64.b64decode(self.encodingAesKey + '=')

    ## 生成回调处理完成后的success加密数据
    def getEncryptedMap(self, content):
        encryptContent = self.encrypt(content)
        timeStamp = str(int(time.time()))
        nonce = self.generateRandomKey(16)
        sign = self.generateSignature(nonce, timeStamp, self.token,encryptContent)
        return {'msg_signature':sign,'encrypt':encryptContent,'timeStamp':timeStamp,'nonce':nonce}

    ##解密钉钉发送的数据
    def getDecryptMsg(self, msg_signature, timeStamp,nonce,  content):
        """
        解密
        :param content:
        :return:
        """
        sign = self.generateSignature(nonce, timeStamp, self.token,content)
        print(sign, msg_signature)
        if msg_signature != sign:
            raise ValueError('signature check error')

        content = base64.decodebytes(content.encode('UTF-8'))  ##钉钉返回的消息体

        iv = self.aesKey[:16]  ##初始向量
        aesDecode = AES.new(self.aesKey, AES.MODE_CBC, iv)
        decodeRes = aesDecode.decrypt(content)
        #pad = int(binascii.hexlify(decodeRes[-1]),16)
        pad = int(decodeRes[-1])
        if pad > 32:
            raise ValueError('Input is not padded or padding is corrupt')
        decodeRes = decodeRes[:-pad]
        l = struct.unpack('!i', decodeRes[16:20])[0]
        ##获取去除初始向量，四位msg长度以及尾部corpid
        nl = len(decodeRes)

        if decodeRes[(20+l):].decode() != self.key:
            raise ValueError('corpId 校验错误')
        return decodeRes[20:(20+l)].decode()

    def encrypt(self, content):
        """
        加密
        :param content:
        :return:
        """
        msg_len = self.length(content)
        content = ''.join([self.generateRandomKey(16) , msg_len.decode() , content , self.key])
        contentEncode = self.pks7encode(content)
        iv = self.aesKey[:16]
        aesEncode = AES.new(self.aesKey, AES.MODE_CBC, iv)
        aesEncrypt = aesEncode.encrypt(contentEncode.encode('UTF-8'))
        return base64.encodebytes(aesEncrypt).decode('UTF-8')

    ### 生成回调返回使用的签名值
    def generateSignature(self, nonce, timestamp, token, msg_encrypt):
        print(type(nonce), type(timestamp), type(token), type(msg_encrypt))
        v = msg_encrypt
        signList = ''.join(sorted([nonce, timestamp, token, v]))
        return hashlib.sha1(signList.encode()).hexdigest()


    def length(self, content):
        """
        将msg_len转为符合要求的四位字节长度
        :param content:
        :return:
        """
        l = len(content)
        return struct.pack('>l', l)

    def pks7encode(self, content):
        """
        安装 PKCS#7 标准填充字符串
        :param text: str
        :return: str
        """
        l = len(content)
        output = io.StringIO()
        val = 32 - (l % 32)
        for _ in range(val):
            output.write('%02x' % val)
        # print "pks7encode",content,"pks7encode", val, "pks7encode", output.getvalue()
        return content + binascii.unhexlify(output.getvalue()).decode()

    def pks7decode(self, content):
        nl = len(content)
        val = int(binascii.hexlify(content[-1]), 16)
        if val > 32:
            raise ValueError('Input is not padded or padding is corrupt')

        l = nl - val
        return content[:l]


    def generateRandomKey(self, size,
                          chars=string.ascii_letters + string.ascii_lowercase + string.ascii_uppercase + string.digits):
        """
        生成加密所需要的随机字符串
        :param size:
        :param chars:
        :return:
        """
        return ''.join(choice(chars) for i in range(size))




if __name__ == '__main__':
    token = "xxxx"
    aes_key = "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus"
    key = "suiteKeyxx"
    dingCrypto = DingCallbackCrypto3(token, aes_key, key)
    content = "{xx:11}"
    t = dingCrypto.getEncryptedMap(content)
    print(t)
    print(t['encrypt'])
    s = dingCrypto.getDecryptMsg(t['msg_signature'],t['timeStamp'],t['nonce'],t['encrypt'])
    print("result:", s)

    test = DingCallbackCrypto3("mryue", "Yue0EfdN5900c1ce5cf6A152c63DDe1808a60c5ecd7", "ding6ccabc44d2c8d38b");

    expect = '{"EventType":"check_url"}'
    res = test.getEncryptedMap(expect)
    print(res)
    text = test.getDecryptMsg("03044561471240d4a14bb09372dfcfd4fd0e40cb", "1608001896814", "WL4PK6yA",
                              '0vJiX6vliEpwG3U45CtXqi+m8PXbQRARJ8p8BbDuD1EMTDf0jKpQ79QS93qEk7XHpP6u+oTTrd15NRPvNvmBKyDCYxxOK+HZeKju4yhELOFchzNukR+t8SB/qk4ROMu3');
    print(text)
    if text == expect:
        print("✅decrypt success")
    else:
        print("❌decrypt failure")

