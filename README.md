# dingtalk-callback-Crypto
钉钉回调加解密类库和对应demo

### Java版本 DingCallbackCrypto.java
1. JDK6,JDK7需要下载JCE无限制权限策略文件
2. 依赖commons-codes包

### python2版本 DingCallbackCrypto2.py

1. 依赖Crypto包进行AES的加解密

### python3版本 DingCallbackCrypto3.py

1. 依赖Crypto包进行AES的加解密


### php版本 DingCallbackCrypto.php

1. 依赖openssl_encrypt方法加解密，版本依赖 (PHP 5 >= 5.3.0, PHP 7)


### 回调处理流程，以java为例

```java
            // 1. 从http请求中获取加解密参数
            String msg_signature = request.getParameter("msg_signature");
            String timeStamp = request.getParameter("timeStamp");
            String nonce = request.getParameter("nonce");
            String encrypt = bodyJson.getString("encrypt");

            // 2. 使用加解密类型
            DingCallbackCrypto callbackCrypto = new DingCallbackCrypto(TOKEN, AES_KEY, OWNER_KEY);
            final String decryptMsg = callbackCrypto.getDecryptMsg(msg_signature, timeStamp, nonce, encrypt);

            // 3. 反序列化回调事件json数据
            JSONObject eventJson = JSON.parseObject(decryptMsg);
            String eventType = eventJson.getString("EventType");

            // 4. 根据EventType分类处理
            if ("check_url".equals(eventType)) {
                // 测试回调url的正确性
            } else if ("user_add_org".equals(eventType)) {
                // 处理通讯录用户增加时间
            } else {
                // 添加其他已注册的
            }

            // 5. 返回success的加密数据
            Map<String, String> successMap = callbackCrypto.getEncryptedMap("success");
            return successMap;

```
