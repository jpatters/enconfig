package enconfig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/spf13/viper"
)

const (
	keyFile  = "%s.key"
	credFile = "%s.yml.enc"
)

var (
	decrypted   []byte
	credsParsed bool
	key         []byte
	environment string
	localFs     fs.FS
)

func LoadKey(dir fs.FS, env string) ([]byte, error) {
	f, err := dir.Open(fmt.Sprintf(keyFile, env))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	encoded, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(encoded))
}

func ReadAndDecryptCredentials(dir fs.FS, env string, key []byte) ([]byte, error) {
	if decrypted != nil {
		return decrypted, nil
	}

	f, err := dir.Open(fmt.Sprintf(credFile, env))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	encrypted, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	decrypted, err = decrypt(encrypted, key)

	return decrypted, err
}

func EncryptAndSaveCredentials(dir fs.FS, env string, data []byte, key []byte) error {
	encrypted, err := encrypt(data, key)
	if err != nil {
		return err
	}

	f, err := dir.Open(fmt.Sprintf(credFile, env))
	if err != nil {
		return err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	return os.WriteFile(stat.Name(), encrypted, 0600)
}

func SetEnvironment(env string) {
	environment = env
}

func SetFS(f fs.FS) {
	localFs = f
}

func MustGetCredential(key string) string {
	if !credsParsed {
		decKey, err := LoadKey(localFs, environment)
		if err != nil {
			panic(err)
		}

		creds, err := ReadAndDecryptCredentials(localFs, environment, decKey)
		if err != nil {
			panic(err)
		}

		viper.SetConfigType("yaml")
		r := bytes.NewReader(creds)
		if err := viper.ReadConfig(r); err != nil {
			panic(err)
		}
		credsParsed = true
	}
	return viper.GetString(key)
}