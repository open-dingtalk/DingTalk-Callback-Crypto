<?php
/**
 * PHP7.1及其之上版本的回调加解密类库
 * 该版本依赖openssl_encrypt方法加解密，注意版本依赖 (PHP 5 >= 5.3.0, PHP 7)
 */
class DingCallbackCrypto
{
    /**
     * @param token          钉钉开放平台上，开发者设置的token
     * @param encodingAesKey 钉钉开放台上，开发者设置的EncodingAESKey
     * @param corpId         企业自建应用-事件订阅, 使用appKey
     *                       企业自建应用-注册回调地址, 使用corpId
     *                       第三方企业应用, 使用suiteKey
     */
    private $m_token;
    private $m_encodingAesKey;
    private $m_corpId;
    //注意这里修改为构造函数
    function __construct($token, $encodingAesKey, $ownerKey)
    {
        $this->m_token = $token;
        $this->m_encodingAesKey = $encodingAesKey;
        $this->m_corpId = $ownerKey;
	}
	
	public function getEncryptedMap($plain){
		$timeStamp = time();
		$pc = new Prpcrypt($this->m_encodingAesKey);
		$nonce= $pc->getRandomStr();
		return $this->getEncryptedMapDetail($plain, $timeStamp, $nonce);
	}

	/**
	 * 加密回调信息
	 */
    public function getEncryptedMapDetail($plain, $timeStamp, $nonce)
    {
        $pc = new Prpcrypt($this->m_encodingAesKey);

        $array = $pc->encrypt($plain, $this->m_corpId);
        $ret = $array[0];
        if ($ret != 0) {
            //return $ret;
			// return ['ErrorCode'=>$ret, 'data' => ''];
			throw new Exception('AES加密错误',ErrorCode::$EncryptAESError);
        }

        if ($timeStamp == null) {
            $timeStamp = time();
        }
        $encrypt = $array[1];

        $sha1 = new SHA1;
        $array = $sha1->getSHA1($this->m_token, $timeStamp, $nonce, $encrypt);
        $ret = $array[0];
        if ($ret != 0) {
            //return $ret;
            throw new Exception('ComputeSignatureError',ErrorCode::$ComputeSignatureError);
        }
        $signature = $array[1];

        $encryptMsg = json_encode(array(
            "msg_signature" => $signature,
            "encrypt" => $encrypt,
            "timeStamp" => $timeStamp,
            "nonce" => $nonce
        ));
        
		return $encryptMsg;
    }

	/**
	 * 解密回调信息
	 */
    public function getDecryptMsg($signature, $timeStamp = null, $nonce, $encrypt)
    {
        if (strlen($this->m_encodingAesKey) != 43) {
            //return ErrorCode::$IllegalAesKey;
			// return ['ErrorCode'=>ErrorCode::$IllegalAesKey, 'data' => ''];
			throw new Exception('IllegalAesKey',ErrorCode::$IllegalAesKey);
        }

        $pc = new Prpcrypt($this->m_encodingAesKey);

        if ($timeStamp == null) {
            $timeStamp = time();
        }

        $sha1 = new SHA1;
        $array = $sha1->getSHA1($this->m_token, $timeStamp, $nonce, $encrypt);
        $ret = $array[0];

        if ($ret != 0) {
            //return $ret;
			// return ['ErrorCode'=>$ret, 'data' => ''];
			throw new Exception('ComputeSignatureError',ErrorCode::$ComputeSignatureError);
        }

        $verifySignature = $array[1];
        if ($verifySignature != $signature) {
            //return ErrorCode::$ValidateSignatureError;
			//return ['ErrorCode'=>ErrorCode::$ValidateSignatureError, 'data' => ''];
			throw new Exception('ValidateSignatureError',ErrorCode::$ValidateSignatureError);
        }

        $result = $pc->decrypt($encrypt, $this->m_corpId);
       
        if ($result[0] != 0) {
            //return $result[0];
			// return ['ErrorCode'=>$result[0], 'data' => ''];
			throw new Exception('DecryptAESError',ErrorCode::$DecryptAESError);
        }
        $decryptMsg = $result[1];
        //return ErrorCode::$OK;
        return $decryptMsg;

    }
}

class SHA1
{
	public function getSHA1($token, $timestamp, $nonce, $encrypt_msg)
	{
		try {
			$array = array($encrypt_msg, $token, $timestamp, $nonce);
			sort($array, SORT_STRING);
			$str = implode($array);
			return array(ErrorCode::$OK, sha1($str));
		} catch (Exception $e) {
			print $e . "\n";
			return array(ErrorCode::$ComputeSignatureError, null);
		}
	}

}

/**
 * error code 说明.
 * <ul>
 *    <li>-900004: encodingAesKey 非法</li>
 *    <li>-900005: 签名验证错误</li>
 *    <li>-900006: sha加密生成签名失败</li>
 *    <li>-900007: aes 加密失败</li>
 *    <li>-900008: aes 解密失败</li>
 *    <li>-900010: suiteKey 校验错误</li>
 * </ul>
 */
class ErrorCode
{
	public static $OK = 0;
	
	public static $IllegalAesKey = 900004;
	public static $ValidateSignatureError = 900005;
	public static $ComputeSignatureError = 900006;
	public static $EncryptAESError = 900007;
	public static $DecryptAESError = 900008;
	public static $ValidateSuiteKeyError = 900010;
}

class PKCS7Encoder
{
	public static $block_size = 32;

	function encode($text)
	{
		$block_size = PKCS7Encoder::$block_size;
		$text_length = strlen($text);
		$amount_to_pad = PKCS7Encoder::$block_size - ($text_length % PKCS7Encoder::$block_size);
		if ($amount_to_pad == 0) {
			$amount_to_pad = PKCS7Encoder::$block_size;
		}
		$pad_chr = chr($amount_to_pad);
		$tmp = "";
		for ($index = 0; $index < $amount_to_pad; $index++) {
			$tmp .= $pad_chr;
		}
		return $text . $tmp;
	}

	function decode($text)
	{
		$pad = ord(substr($text, -1));
		if ($pad < 1 || $pad > PKCS7Encoder::$block_size) {
			$pad = 0;
		}
		return substr($text, 0, (strlen($text) - $pad));
	}

}


class Prpcrypt
{
	public $key;

	function __construct($k)
	{
		$this->key = base64_decode($k . "=");
	}

	public function encrypt($text, $corpid)
	{

		try {
			//获得16位随机字符串，填充到明文之前
			$random = $this->getRandomStr();
            $text = $random . pack("N", strlen($text)) . $text . $corpid;
            $iv = substr($this->key, 0, 16);

			// 网络字节序
			// $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
			// $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
			
			//使用自定义的填充方式对明文进行补位填充
			$pkc_encoder = new PKCS7Encoder;
			$text = $pkc_encoder->encode($text);
			// mcrypt_generic_init($module, $this->key, $iv);
			// //加密
			// $encrypted = mcrypt_generic($module, $text);
			// mcrypt_generic_deinit($module);
            // mcrypt_module_close($module);
        

            

            $encrypted = openssl_encrypt($text, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv );

			//print(base64_encode($encrypted));
			//使用BASE64对加密后的字符串进行编码
			return array(ErrorCode::$OK, base64_encode($encrypted));
		} catch (Exception $e) {
			print $e;
			return array(ErrorCode::$EncryptAESError, null);
		}
	}

	public function decrypt($encrypted, $corpid)
	{

		try {
			$ciphertext_dec = base64_decode($encrypted);
			// $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
			$iv = substr($this->key, 0, 16);
			// mcrypt_generic_init($module, $this->key, $iv);

			// $decrypted = mdecrypt_generic($module, $ciphertext_dec);
			// mcrypt_generic_deinit($module);
            // mcrypt_module_close($module);
            
            $decrypted = openssl_decrypt ( $ciphertext_dec, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv );

        
           // return $decrypted;
		} catch (Exception $e) {
			return array(ErrorCode::$DecryptAESError, null);
		}


		try {
			//去除补位字符
			$pkc_encoder = new PKCS7Encoder;
			$result = $pkc_encoder->decode($decrypted);
			//去除16位随机字符串,网络字节序和AppId
			if (strlen($result) < 16)
                return "";
			$content = substr($result, 16, strlen($result));
			$len_list = unpack("N", substr($content, 0, 4));
			$xml_len = $len_list[1];
			$xml_content = substr($content, 4, $xml_len);
			$from_corpid = substr($content, $xml_len + 4);
		} catch (Exception $e) {
			print $e;
			return array(ErrorCode::$DecryptAESError, null);
		}
		if ($from_corpid != $corpid)
            return array(ErrorCode::$ValidateSuiteKeyError, null);
            
        
		return array(0, $xml_content);

	}

	function getRandomStr()
	{

		$str = "";
		$str_pol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
		$max = strlen($str_pol) - 1;
		for ($i = 0; $i < 16; $i++) {
			$str .= $str_pol[mt_rand(0, $max)];
		}
		return $str;
	}

}


/**
 * 以下为开发者需要自行构造的接口(也就是回调url)，接口内调用demo类中的解密和加密方法即可
 */

function test_demo(){
	// 构造加解密方法
    $crypt = new DingCallbackCrypto("token", "aes_key", "ownerKey");
	// 解密方法； data为钉钉服务器请求开发者该接口时携带的参数(msg_signature,timeStamp和nonce在request中，encrypt在body中)
    $text = $crypt->getDecryptMsg($data->msg_signature, $data->timeStamp, $data->nonce, $data->encrypt);
	    var_dump($text);
	// 加密返回；参数固定传success字符串，该方法得到的信息直接返回给钉钉服务器即可
    $res = $crypt->getEncryptedMap("success");
    var_dump($res);
}

test_demo();
?>
