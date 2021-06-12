#! ruby
# frozen_string_literal: true

require 'securerandom'
require 'base64'
require 'digest/sha1'
require 'openssl'

class DingCallbackCrypto
  attr_reader :token, :encoding_aes_key, :key

  # arguments
  #   token:             钉钉开放平台上，开发者设置的 token
  #   encoding_aes_key:  钉钉开放台上，开发者设置的 encodingAESKey
  #   key:               企业自建应用-事件订阅, 使用 appKey
  #                      企业自建应用-注册回调地址, 使用 corpId
  #                      第三方企业应用, 使用 suiteKey
  def initialize(token, encoding_aes_key, key)
    @token = token
    @encoding_aes_key = encoding_aes_key
    @key = key
  end

  def encrypt_message(content)
    encrypt = encrypt(content)
    time_stamp = Time.now.to_i.to_s
    nonce = SecureRandom.hex(8)
    sign = generate_signature(encrypt, time_stamp, nonce)

    {
      encrypt: encrypt,
      timeStamp: time_stamp,
      msg_signature: sign,
      nonce: nonce
    }
  end

  def decrypt_message(msg_signature, encrypted, time_stamp, nonce)
    sign = generate_signature(encrypted, time_stamp, nonce)
    raise 'signature is invalid'  if msg_signature != sign

    raw = Base64.decode64(encrypted)
    raw = dispatch_cipher(:decrypt, raw)
    parsed = PKCS7Encoder.decode(raw)
    result = parsed[16...parsed.length]
    len_list = result[0...4].unpack('N')
    content_len = len_list.first
    content = result[4...4 + content_len]
    from_key= result[content_len + 4...result.size]
    raise 'from key is not equal to key' if from_key != key

    content
  end

  private

  def encrypt(content)
    length = [content.length].pack('N')
    text = [SecureRandom.hex(8), length, content, key].join
    text = PKCS7Encoder.encode(text)
    text = dispatch_cipher(:encrypt, text)
    Base64.encode64(text)
  end

  def generate_signature(content, nonce, time_stamp)
    Digest::SHA1.hexdigest([nonce, time_stamp, token, content].sort.join)
  end

  def dispatch_cipher(action, text)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.send(action)
    cipher.padding = 0
    cipher.key     = aes_key
    cipher.iv      = aes_key[0...16]
    cipher.update(text) + cipher.final
  end

  def aes_key
    @aes_key ||= Base64.decode64("#{encoding_aes_key}=")
  end

  module PKCS7Encoder
    extend self

    BLOCK_SIZE = 32

    def decode(text)
      pad = text[-1].ord
      pad = 0 if (pad < 1 || pad > BLOCK_SIZE)
      size = text.size - pad
      text[0...size]
    end

    def encode(text)
      amount_to_pad = BLOCK_SIZE - (text.length % BLOCK_SIZE)
      amount_to_pad = BLOCK_SIZE if amount_to_pad == 0
      pad_chr = amount_to_pad.chr
      "#{text}#{pad_chr * amount_to_pad}"
    end
  end
end

class DingCallbackCryptoTest
  TOKEN = 'xxxCfDersZufjh9bRhYVZsn6oF5qHI4jRg7HAsJve91Jxxxxx'
  ENCODING_AES_KEY = 'xxxGjXo6Xn9N6x1cDAIG5tEJvwwWZ6Wjgpt4vmxxxxx'
  APP_KEY = 'dingb4qzb2djxnqxxxxx'

  def self.run
    instance  = DingCallbackCrypto.new(TOKEN, ENCODING_AES_KEY, APP_KEY)
    encrypted = instance.encrypt_message('success')
    raw = instance.decrypt_message(*encrypted.slice(:msg_signature, :encrypt, :timeStamp, :nonce).values)
    puts raw == 'success'
  end
end

# DingCallbackCryptoTest.run