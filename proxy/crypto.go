package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func aesCbcDecrypt(payload, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return payload, err
	}

	if len(payload)%block.BlockSize() != 0 {
		return payload, fmt.Errorf("invalid ciphertext block size")
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	decPayload := make([]byte, len(payload))
	cbc.CryptBlocks(decPayload, payload)
	payload = pkcsUnpad(decPayload) //decPayload

	return payload, nil
}

func pkcsUnpad(buf []byte) []byte {
	bufLen := len(buf)
	unpadding := int(buf[bufLen-1])
	return buf[:(bufLen - unpadding)]
}

func aesCbcEncrypt(payload, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return payload, err
	}

	payload = pkcsPad(payload, block.BlockSize())

	cbc := cipher.NewCBCEncrypter(block, iv)
	encPayload := make([]byte, len(payload))
	cbc.CryptBlocks(encPayload, payload)
	payload = encPayload

	return payload, nil
}

func pkcsPad(payload []byte, blockSize int) []byte {
	padding := blockSize - len(payload)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(payload, padText...)
}

func hmacVerify(payload, key, sig []byte) error {
	sum, err := hmacSum(payload, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(sig, sum) {
		return fmt.Errorf("invalid HMAC sum: expected \"%s\", got \"%s\"", hex.EncodeToString(sig), hex.EncodeToString(sum))
	}

	return nil
}

func hmacSum(payload, key []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	if _, err := h.Write(payload); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
