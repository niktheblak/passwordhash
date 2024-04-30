package bcrypt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testPassword = []byte("str0ng_p4ssw0rd")
	prefix       = []byte("$2a")
)

func TestPrefix(t *testing.T) {
	hasher := new(Bcrypt)
	hash, err := hasher.Hash(testPassword)
	require.NoError(t, err)
	t.Log(string(hash))
	assert.True(t, bytes.HasPrefix(hash, prefix))
}

func BenchmarkGenerateFromPassword(b *testing.B) {
	hasher := new(Bcrypt)
	for i := 0; i < b.N; i++ {
		_, err := hasher.Hash(testPassword)
		require.NoError(b, err)
	}
}

func TestInvalidPrefix(t *testing.T) {
	hasher := new(Bcrypt)
	err := hasher.Compare([]byte("$1sababababababababababa"), testPassword)
	assert.EqualError(t, err, "crypto/bcrypt: hashedSecret too short to be a bcrypted password")
}

func TestTooShortHash(t *testing.T) {
	hasher := new(Bcrypt)
	err := hasher.Compare([]byte("$2aab"), testPassword)
	assert.EqualError(t, err, "crypto/bcrypt: hashedSecret too short to be a bcrypted password")
}

func TestNilInput(t *testing.T) {
	hasher := new(Bcrypt)
	err := hasher.Compare(nil, testPassword)
	assert.Error(t, err)
}

func TestCompareHashAndPassword(t *testing.T) {
	hasher := new(Bcrypt)
	hash, err := hasher.Hash(testPassword)
	t.Log(string(hash))
	require.NoError(t, err)
	err = hasher.Compare(hash, testPassword)
	assert.NoError(t, err, "Password did not match")
	err = hasher.Compare(hash, []byte("wrong password"))
	assert.EqualError(t, err, "crypto/bcrypt: hashedPassword is not the hash of the given password")
}

func BenchmarkCompareHashAndPassword(b *testing.B) {
	hasher := new(Bcrypt)
	hash, err := hasher.Hash(testPassword)
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		err = hasher.Compare(hash, testPassword)
		require.NoError(b, err)
	}
}
