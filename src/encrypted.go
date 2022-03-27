package step

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

// 进行加密解密的数据
type SourceData struct {
	Data   []byte
	Secret []byte
}

// 用于数据加密解密
type Encryptor interface {
	Encode(sd *SourceData) error
	Decode(sd *SourceData) error
}

// AES 加密实现的接口
type AESEncryptor struct{}

// Encode source data encode
func (AESEncryptor) Encode(sd *SourceData) error {
	sd.Data = aesEncrypt(sd.Data, sd.Secret)
	return nil
}

// Decode source data decode
func (AESEncryptor) Decode(sd *SourceData) error {
	sd.Data = aesDecrypt(sd.Data, sd.Secret)
	return nil
}

// aesEncrypt ASE encode
func aesEncrypt(origData, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	result := make([]byte, len(origData))
	blockMode.CryptBlocks(result, origData)
	return result
}

// aesDecrypt  aes decode
func aesDecrypt(bytes, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	orig := make([]byte, len(bytes))
	blockMode.CryptBlocks(orig, bytes)
	orig = PKCS7UnPadding(orig)
	return orig
}

// PKCS7Padding complement
func PKCS7Padding(ciphertext []byte, blksize int) []byte {
	padding := blksize - len(ciphertext)%blksize
	plaintext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, plaintext...)
}

// PKCS7UnPadding to the code
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	padding := int(origData[length-1])
	return origData[:(length - padding)]
}
