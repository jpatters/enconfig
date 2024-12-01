package enconfig

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

func (cr *CredentialsReader) parseData(encryptedData []byte) (cipherText []byte, iv []byte, err error) {
	var (
		authData []byte
	)

	segments := strings.Split(string(encryptedData), "--")

	if len(segments) < 3 {
		return nil, nil, errors.New("invalid number of data segments: check data file")
	}

	if cipherText, err = base64.StdEncoding.DecodeString(segments[0]); err != nil {
		return nil, nil, err
	}

	if iv, err = base64.StdEncoding.DecodeString(segments[1]); err != nil {
		return nil, nil, err
	}

	if authData, err = base64.StdEncoding.DecodeString(segments[2]); err != nil {
		return nil, nil, err
	}

	return bytes.Join([][]byte{cipherText, authData}, []byte{}), iv, nil
}

func (cr *CredentialsReader) decrypt(key []byte, ciphertext []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}

func deserialize(buf []byte) ([]byte, error) {
	const (
		ASCII8bit      = 0x22
		OFFSET_2_BYTES = 0x02
		OFFSET_4_BYTES = 0x03
		OFFSET_5_BYTES = 0x04
	)
	var (
		header       = buf[:2]
		objType      = buf[2]
		lenIndicator = buf[3]
	)

	if !bytes.Equal(header, []byte{0x04, 0x08}) {
		return nil, errors.New("invalid serialization header")
	}
	if objType != ASCII8bit {
		return nil, errors.New("data does not encode an ASCII-8BIT value")
	}

	/*
	  see https://docs.ruby-lang.org/en/2.1.0/marshal_rdoc.html
	*/
	switch lenIndicator {
	case OFFSET_2_BYTES:
		// Following two bytes store length
		length := binary.LittleEndian.Uint16(buf[4:6])
		return buf[6:(length + 6)], nil
	case OFFSET_4_BYTES:
		// Following four bytes store length
		length := binary.LittleEndian.Uint16(buf[4:7])
		return buf[7:(length + 7)], nil
	case OFFSET_5_BYTES:
		// Following five bytes store length
		length := binary.LittleEndian.Uint16(buf[4:8])
		return buf[8:(length + 8)], nil
	case 0x01, 0xff, 0xfe, 0xfd, 0xfc:
		return nil, errors.New("unsupported string length")
	default:
		// In this case, length indicator defined as "object length + 5"
		// so we reduce it by one to get the byte array offset
		return buf[4 : lenIndicator-1], nil
	}
}
