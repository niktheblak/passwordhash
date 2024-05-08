package argon2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testPassword = []byte("str0ng_p4ssw0rd")
	testSalt     = []byte("s0m3_s4lt")
)

func BenchmarkGenerateFromPassword(b *testing.B) {
	hasher := new(Argon2)
	for i := 0; i < b.N; i++ {
		_, err := hasher.HashWithSalt(testPassword, testSalt)
		require.NoError(b, err)
	}
}

func TestInvalidPrefix(t *testing.T) {
	hasher := new(Argon2)
	err := hasher.CompareSalted([]byte("$1sababababababababababa"), testPassword, testSalt)
	assert.EqualError(t, err, "password does not match hash")
}

func TestTooShortHash(t *testing.T) {
	hasher := new(Argon2)
	err := hasher.CompareSalted([]byte("$2aab"), testPassword, testSalt)
	assert.EqualError(t, err, "password does not match hash")
}

func TestNilInput(t *testing.T) {
	hasher := new(Argon2)
	err := hasher.CompareSalted(nil, testPassword, testSalt)
	assert.Error(t, err)
}

func TestCompareHashAndPassword(t *testing.T) {
	hasher := new(Argon2)
	hash, err := hasher.HashWithSalt(testPassword, testSalt)
	t.Log(string(hash))
	require.NoError(t, err)
	err = hasher.CompareSalted(hash, testPassword, testSalt)
	assert.NoError(t, err, "Password did not match")
	err = hasher.CompareSalted(hash, []byte("wrong password"), testSalt)
	assert.EqualError(t, err, "password does not match hash")
}

func BenchmarkCompareHashAndPassword(b *testing.B) {
	hasher := new(Argon2)
	hash, err := hasher.HashWithSalt(testPassword, testSalt)
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		err = hasher.CompareSalted(hash, testPassword, testSalt)
		require.NoError(b, err)
	}
}
