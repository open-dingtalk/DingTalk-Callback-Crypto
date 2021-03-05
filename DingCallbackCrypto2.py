#!/usr/bin/env python
# -*- coding: utf-8 -*-
#  code copy from https://github.com/shuizhengqi1/DingCrypto/blob/master/DingCrypto.py
# 依赖Crypto包


import uuid
import struct
import base64
import hashlib
import time
import logging
from Crypto.Cipher import AES

import StringIO,base64, binascii, hashlib, string, struct
from random import choice
from Crypto.Cipher import AES

"""
@param token          钉钉开放平台上，开发者设置的token
@param encodingAesKey 钉钉开放台上，开发者设置的EncodingAESKey
@param corpId         企业自建应用-事件订阅, 使用appKey
                      企业自建应用-注册回调地址, 使用corpId
                      第三方企业应用, 使用suiteKey
"""
class DingCallbackCrypto2:
    def __init__(self, token,encodingAesKey, key):
        self.encodingAesKey = encodingAesKey
        self.key = key
        self.token = token
        self.aesKey = base64.b64decode(self.encodingAesKey + '=')

    def getEncryptedMap(self, content):
        encryptContent = self.encrypt(content)
        timeStamp = str(time.time())
        nonce = self.generateRandomKey(16)
        sign = self.generateSignature(nonce, timeStamp, self.token,encryptContent)
        return {'msg_signature':sign,'encrypt':encryptContent,'timeStamp':timeStamp,'nonce':nonce}

    def encrypt(self, content):
        """
        加密
        :param content:
        :return:
        """
        msg_len = self.length(content)
        content = self.generateRandomKey(16) + msg_len + content + self.key
        contentEncode = self.pks7encode(content)
        iv = self.aesKey[:16]
        aesEncode = AES.new(self.aesKey, AES.MODE_CBC, iv)
        aesEncrypt = aesEncode.encrypt(contentEncode)
        return base64.encodestring(aesEncrypt).replace('\n', '')

    ##解密钉钉发送的数据
    def getDecryptMsg(self, msg_signature, timeStamp,nonce,  content):
        """
        解密
        :param content:
        :return:
        """
        sign = self.generateSignature(nonce, timeStamp, self.token,content)
        if msg_signature != sign:
            raise ValueError('signature check error')

        content = base64.decodestring(content)  ##钉钉返回的消息体

        iv = self.aesKey[:16]  ##初始向量
        aesDecode = AES.new(self.aesKey, AES.MODE_CBC, iv)
        decodeRes = aesDecode.decrypt(content)
        pad = int(binascii.hexlify(decodeRes[-1]),16)
        if pad > 32:
            raise ValueError('Input is not padded or padding is corrupt')
        decodeRes = decodeRes[:-pad]
        l = struct.unpack('!i', decodeRes[16:20])[0]
        ##获取去除初始向量，四位msg长度以及尾部corpid
        nl = len(decodeRes)
        val = int(binascii.hexlify(decodeRes[-1]), 16)
        
        if decodeRes[(20+l):] != self.key:
            raise ValueError('corpId 校验错误')
        return decodeRes[20:(20+l)]
        

    ### 生成回调返回使用的签名值
    def generateSignature(self, nonce, timestamp, token, msg_encrypt):
        signList = ''.join(sorted([nonce, timestamp, token, msg_encrypt]))
        return hashlib.sha1(signList).hexdigest()


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
        output = StringIO.StringIO()
        val = 32 - (l % 32)
        for _ in xrange(val):
            output.write('%02x' % val)
        # print "pks7encode",content,"pks7encode", val, "pks7encode", output.getvalue()
        return content + binascii.unhexlify(output.getvalue())

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
    dingCrypto = DingCallbackCrypto2("xxxx", "o1w0aum42yaptlz8alnhwikjd3jenzt9cb9wmzptgus", "suiteKeyxx")
    t = dingCrypto.getEncryptedMap("{xx:11}")
    print(t)
    s = dingCrypto.getDecryptMsg(t['msg_signature'],t['timeStamp'],t['nonce'],t['encrypt'])
    print("result:",s)