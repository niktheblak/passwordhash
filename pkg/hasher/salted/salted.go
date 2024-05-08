package salted

import (
	"crypto/subtle"

	"github.com/niktheblak/passwordhash/pkg/hasher"
)

type Hasher struct {
	Hasher hasher.Hasher
	Salt   []byte
}

func (sh *Hasher) CompareSalted(passwordHash, password, salt []byte) error {
	expectedHash, err := sh.HashWithSalt(password, salt)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(passwordHash, expectedHash) != 1 {
		return hasher.ErrInvalidPassword
	}
	return nil
}

func (sh *Hasher) HashWithSalt(password, salt []byte) ([]byte, error) {
	saltedPassword := make([]byte, 0, len(salt)+len(password))
	saltedPassword = append(saltedPassword, salt...)
	saltedPassword = append(saltedPassword, password...)
	return sh.Hasher.Hash(saltedPassword)
}

func (sh *Hasher) Hash(data []byte) (hash []byte, err error) {
	salt, err := EnsureSalt(sh.Salt)
	sh.Salt = salt
	hash, err = sh.HashWithSalt(data, salt)
	if err != nil {
		return
	}
	saltAndHash := make([]byte, 0, 1+len(salt)+len(hash))
	saltAndHash = append(saltAndHash, byte(len(salt)))
	saltAndHash = append(saltAndHash, salt...)
	saltAndHash = append(saltAndHash, hash...)
	return saltAndHash, nil
}

func (sh *Hasher) Compare(passwordHash, password []byte) error {
	givenHash, salt, err := Split(passwordHash)
	if err != nil {
		return err
	}
	sh.Salt = salt
	return sh.CompareSalted(givenHash, password, salt)
}

func Wrap(h hasher.Hasher, salt []byte) *Hasher {
	return &Hasher{
		Hasher: h,
		Salt:   salt,
	}
}
