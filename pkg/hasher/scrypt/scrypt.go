package scrypt

import (
	"crypto/subtle"
	"encoding/base64"

	stdscrypt "golang.org/x/crypto/scrypt"

	"github.com/niktheblak/passwordhash/pkg/hasher"
)

const (
	DefaultN      = 32768
	DefaultR      = 8
	DefaultP      = 1
	DefaultKeyLen = 32
	SaltLen       = 8
)

var (
	Encoding   = base64.RawURLEncoding
	HashPrefix = []byte{'$', '1', 's'}
)

type Scrypt struct {
}

func (s *Scrypt) CompareSalted(passwordHash, password, salt []byte) error {
	expected, err := s.HashWithSalt(password, salt)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(passwordHash, expected) != 1 {
		return hasher.ErrInvalidPassword
	}
	return nil
}

func (s *Scrypt) HashWithSalt(password, salt []byte) ([]byte, error) {
	return stdscrypt.Key(password, salt, DefaultN, DefaultR, DefaultP, DefaultKeyLen)
}
