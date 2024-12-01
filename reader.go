package enconfig

import (
	"bytes"
	"encoding/hex"
	"os"
)

// CredentialsReader is an io.Reader which understands the encrypted Rails
// credentials file format, and given a decryption key, returns its unencrypted
// contents.
type CredentialsReader struct {
	KeyPath   string // path to decryption key (e.g. 'master.key')
	Path      string // path of encrypted file (e.g. 'credentials.yml.enc')
	decrypted *bytes.Buffer
	parsed    bool
}

// Read implements io.Reader interface.
//
// This method will return an error if the associated KeyPath or Path are not valid,
// or if the encrypted file can not be parsed or deserialized.
//
// # See Also
//
//   - https://docs.ruby-lang.org/en/2.1.0/marshal_rdoc.html for a description of how
//     the encrypted file format is deserialized into YAML.
//   - https://pkg.go.dev/github.com/spf13/viper#ReadConfig to see how the
//     YAML data is handled by the server.
func (cr *CredentialsReader) Read(p []byte) (int, error) {
	if cr.decrypted == nil {

		var (
			key           []byte
			encryptedData []byte
			cipherText    []byte
			iv            []byte
			err           error
		)

		if encryptedData, err = os.ReadFile(cr.Path); err != nil {
			return 0, err
		}

		if key, err = cr.readKey(cr.KeyPath); err != nil {
			return 0, err
		}

		if cipherText, iv, err = cr.parseData(encryptedData); err != nil {
			return 0, err
		}

		res := cr.decrypt(key, cipherText, iv)

		// Extract payload from Rails binary format
		if res, err = deserialize(res); err != nil {
			return 0, err
		}

		cr.decrypted = bytes.NewBuffer(res)
	}
	return cr.decrypted.Read(p)
}

const (
	// name used to read master key from execution environment
	railsEnvKey = "RAILS_MASTER_KEY"
)

func (cr *CredentialsReader) readKey(keyPath string) ([]byte, error) {
	if envKey := os.Getenv(railsEnvKey); len(envKey) > 0 {
		return hex.DecodeString(envKey)
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	key = bytes.TrimSpace(key)

	if key, err = hex.DecodeString(string(key)); err != nil {
		return nil, err
	}

	return key, nil
}
