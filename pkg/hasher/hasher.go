package hasher

import (
	"errors"
)

var (
	ErrHashTooShort      = errors.New("hashed password is too short")
	ErrInvalidHashPrefix = errors.New("invalid hash prefix")
	ErrInvalidPassword   = errors.New("password does not match hash")
	ErrInvalidSalt       = errors.New("invalid salt length")
)

type Hasher interface {
	Hash(data []byte) (hash []byte, err error)
	Compare(passwordHash, password []byte) error
}
