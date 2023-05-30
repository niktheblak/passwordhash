package argon2

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testPassword = []byte("str0ng_p4ssw0rd")
	testSalt     = []byte("s0m3_s4lt")
	prefix       = []byte("$2a")
)

func TestPrefix(t *testing.T) {
	hash, err := GenerateFromPassword(testPassword, testSalt)
	require.NoError(t, err)
	t.Log(string(hash))
	assert.True(t, bytes.HasPrefix(hash, prefix))
}

func BenchmarkGenerateFromPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateFromPassword(testPassword, testSalt)
		require.NoError(b, err)
	}
}

func TestInvalidPrefix(t *testing.T) {
	err := CompareHashAndPassword([]byte("$1sababababababababababa"), testPassword, testSalt)
	assert.EqualError(t, err, "crypto/bcrypt: hashedSecret too short to be a bcrypted password")
}

func TestTooShortHash(t *testing.T) {
	err := CompareHashAndPassword([]byte("$2aab"), testPassword, testSalt)
	assert.EqualError(t, err, "crypto/bcrypt: hashedSecret too short to be a bcrypted password")
}

func TestNilInput(t *testing.T) {
	err := CompareHashAndPassword(nil, testPassword, testSalt)
	assert.Error(t, err)
}

func TestCompareHashAndPassword(t *testing.T) {
	hash, err := GenerateFromPassword(testPassword, testSalt)
	t.Log(string(hash))
	require.NoError(t, err)
	err = CompareHashAndPassword(hash, testPassword, testSalt)
	assert.NoError(t, err, "Password did not match")
	err = CompareHashAndPassword(hash, []byte("wrong password"), testSalt)
	assert.EqualError(t, err, "crypto/bcrypt: hashedPassword is not the hash of the given password")
}

func BenchmarkCompareHashAndPassword(b *testing.B) {
	hash, err := GenerateFromPassword(testPassword, testSalt)
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		err = CompareHashAndPassword(hash, testPassword, testSalt)
		require.NoError(b, err)
	}
}
