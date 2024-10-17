package reloader

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
)

const (
	innerKey           = "alaudaALAUDAalauda"
	nonceSize          = 12
	halfNonceSize      = nonceSize / 2
	aefHeader          = "AEF"
	aefPemEncodeEnable = "AEF_PEM_ENCODE_ENABLE"
)

func Encrypt(src []byte) ([]byte, error) {
	if src == nil {
		return src, nil
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return src, err
	}

	h := hmac.New(sha256.New, []byte(innerKey))
	h.Write(nonce)
	key := h.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return src, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return src, err
	}

	out := aesGCM.Seal(nil, nonce, src, nil)
	final := append(nonce[:halfNonceSize], out...)
	final = append(final, nonce[halfNonceSize:]...)
	final = []byte(aefHeader + hex.EncodeToString(final))
	return final, nil
}

func WriteFile(name string, data []byte, perm fs.FileMode) error {
	if os.Getenv(aefPemEncodeEnable) == "true" {
		dst, err := Encrypt(data)
		if err != nil {
			return fmt.Errorf("aef encrypt file error: " + err.Error())
		}
		data = dst
	}
	return os.WriteFile(name, data, perm)
}
