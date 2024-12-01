package enconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func SaveKey(key []byte, env string) error {
	filename := fmt.Sprintf("%s.key", env)
	encoded := base64.StdEncoding.EncodeToString(key)
	return os.WriteFile(filename, []byte(encoded), 0600)
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func CreateEmptyCredentials(env string, key []byte) error {
	emptyData, err := yaml.Marshal(map[string]interface{}{})
	if err != nil {
		return err
	}

	encrypted, err := encrypt(emptyData, key)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.yml.enc", env)
	return os.WriteFile(filename, encrypted, 0644)
}
