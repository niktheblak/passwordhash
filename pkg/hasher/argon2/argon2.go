package argon2

import (
	"crypto/subtle"

	"golang.org/x/crypto/argon2"

	"github.com/niktheblak/passwordhash/pkg/hasher"
)

const (
	Time    = 3
	Memory  = 32 * 1024
	Threads = 4
	KeyLen  = 32
)

type Argon2 struct {
}

func (h *Argon2) CompareSalted(passwordHash, password, salt []byte) error {
	hash := argon2.IDKey(password, salt, Time, Memory, Threads, KeyLen)
	if subtle.ConstantTimeCompare(passwordHash, hash) != 1 {
		return hasher.ErrInvalidPassword
	}
	return nil
}

func (h *Argon2) HashWithSalt(password, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, hasher.ErrInvalidSalt
	}
	hash := argon2.IDKey(password, salt, Time, Memory, Threads, KeyLen)
	return hash, nil
}
