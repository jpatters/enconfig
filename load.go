package enconfig

import (
	"github.com/spf13/viper"
)

var (
	creds                    *CredentialsReader
	encCredentialFilePath    string
	encCredentialKeyFilePath string
)

func mustGetCredential(key string) string {
	if creds == nil {
		creds = &CredentialsReader{
			Path:    encCredentialFilePath,
			KeyPath: encCredentialKeyFilePath,
		}
		viper.SetConfigType("yaml")
		if err := viper.ReadConfig(creds); err != nil {
			panic(err)
		}
		creds.parsed = true
	}
	return viper.GetString(key)
}
