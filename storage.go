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
	decrypted        []byte
	credsParsed      bool
	localEnvironment string
	localFs          fs.FS
	keyEnv           = os.Getenv("ENCONFIG_KEY")
)

func LoadKey(dir fs.FS, env string) ([]byte, error) {
	var encoded []byte
	if keyEnv == "" {
		f, err := dir.Open(fmt.Sprintf(keyFile, env))
		if err != nil {
			return nil, err
		}
		defer f.Close()

		encoded, err = io.ReadAll(f)
		if err != nil {
			return nil, err
		}
	} else {
		encoded = []byte(keyEnv)
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
	localEnvironment = env
}

func SetFS(f fs.FS) {
	localFs = f
}

func MustGetCredential(key string) string {
	if !credsParsed {
		decKey, err := LoadKey(localFs, localEnvironment)
		if err != nil {
			panic(err)
		}

		creds, err := ReadAndDecryptCredentials(localFs, localEnvironment, decKey)
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
