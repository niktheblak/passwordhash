package salted

import (
	"crypto/rand"

	"github.com/niktheblak/passwordhash/pkg/hasher"
)

const DefaultSaltLength = 8

func GenerateSalt(n int) ([]byte, error) {
	salt := make([]byte, n)
	_, err := rand.Read(salt)
	return salt, err
}

func EnsureSalt(salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return GenerateSalt(DefaultSaltLength)
	}
	return salt, nil
}

func Split(passwordHash []byte) (password []byte, salt []byte, err error) {
	saltLen := int(passwordHash[0])
	if saltLen <= 0 || saltLen >= 128 {
		// the length byte is likely invalid
		err = hasher.ErrInvalidHashPrefix
		return
	}
	if len(passwordHash) <= saltLen+1 {
		// the byte slice is too short to contain both the salt and the password hash
		err = hasher.ErrInvalidHashPrefix
		return
	}
	salt = passwordHash[:saltLen]
	password = passwordHash[saltLen:]
	return
}
