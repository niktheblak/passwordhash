package scrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	stdscrypt "golang.org/x/crypto/scrypt"
)

const (
	DefaultN      = 32768
	DefaultR      = 8
	DefaultP      = 1
	DefaultKeyLen = 32
	SaltLen       = 8
)

var (
	ErrHashTooShort              = errors.New("hashed password is too short")
	ErrMismatchedHashAndPassword = errors.New("hashed password does not match")
	ErrInvalidHashPrefix         = errors.New("invalid hash prefix")
)

var (
	Encoding   = base64.RawURLEncoding
	HashPrefix = []byte{'$', '1', 's'}
)

func DecodeSaltAndHash(encodedHash []byte) (salt []byte, hash []byte, err error) {
	if !bytes.HasPrefix(encodedHash, HashPrefix) {
		err = ErrInvalidHashPrefix
		return
	}
	encodedHash = encodedHash[len(HashPrefix):]
	decoded := make([]byte, Encoding.DecodedLen(len(encodedHash)))
	n, err := Encoding.Decode(decoded, encodedHash)
	if err != nil {
		return
	}
	decoded = decoded[:n]
	if len(decoded) < SaltLen {
		err = ErrHashTooShort
		return
	}
	salt = decoded[:SaltLen]
	hash = decoded[SaltLen:]
	return
}

func CompareHashAndPassword(hashedPassword, password []byte) error {
	salt, hash, err := DecodeSaltAndHash(hashedPassword)
	if err != nil {
		return err
	}
	expected, err := HashWithSalt(salt, password)
	if err != nil {
		return err
	}
	res := subtle.ConstantTimeCompare(hash, expected)
	if res == 1 {
		return nil
	}
	return ErrMismatchedHashAndPassword
}

func HashWithSalt(salt, password []byte) ([]byte, error) {
	return stdscrypt.Key(password, salt, DefaultN, DefaultR, DefaultP, DefaultKeyLen)
}

func Hash(password []byte) (salt []byte, hash []byte, err error) {
	salt = make([]byte, SaltLen)
	_, err = rand.Read(salt)
	if err != nil {
		return
	}
	hash, err = HashWithSalt(salt, password)
	return
}

func GenerateFromPassword(password []byte) (encodedHash []byte, err error) {
	var buf bytes.Buffer
	enc := base64.NewEncoder(Encoding, &buf)
	salt, hash, err := Hash(password)
	if err != nil {
		return
	}
	enc.Write(salt)
	enc.Write(hash)
	enc.Close()
	var encoded bytes.Buffer
	encoded.Write(HashPrefix)
	buf.WriteTo(&encoded)
	encodedHash = encoded.Bytes()
	return
}
