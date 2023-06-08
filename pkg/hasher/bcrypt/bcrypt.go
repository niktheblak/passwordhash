package bcrypt

import (
	"golang.org/x/crypto/bcrypt"
)

var (
	HashPrefix = []byte{'$', '1', 'b'}
)

type Bcrypt struct {
}

func (b *Bcrypt) Hash(data []byte) (hash []byte, err error) {
	return bcrypt.GenerateFromPassword(data, bcrypt.DefaultCost)
}

func (b *Bcrypt) Compare(passwordHash, password []byte) error {
	return bcrypt.CompareHashAndPassword(passwordHash, password)
}
