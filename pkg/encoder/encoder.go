package encoder

import (
	"bytes"
	"encoding/base64"

	"github.com/niktheblak/passwordhash/pkg/hasher"
)

type Encoder struct {
	Prefix   []byte
	Salt     []byte
	Hash     []byte
	Encoding *base64.Encoding
}

func (e *Encoder) Encode() ([]byte, error) {
	if len(e.Salt) == 0 {
		return nil, hasher.ErrInvalidSalt
	}
	if len(e.Hash) == 0 {
		return nil, hasher.ErrHashTooShort
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(e.Salt)))
	buf.Write(e.Salt)
	buf.Write(e.Hash)
	if e.Encoding == nil {
		return buf.Bytes(), nil
	}
	encBuf := new(bytes.Buffer)
	if len(e.Prefix) > 0 {
		encBuf.Write(e.Prefix)
	}
	enc := base64.NewEncoder(e.Encoding, encBuf)
	if _, err := buf.WriteTo(enc); err != nil {
		return nil, err
	}
	return encBuf.Bytes(), nil
}

type Decoder struct {
	Prefix   []byte
	Encoding *base64.Encoding
}

func (d *Decoder) Decode(encodedHash []byte) (salt []byte, hash []byte, err error) {
	if len(d.Prefix) > 0 && !bytes.HasPrefix(encodedHash, d.Prefix) {
		err = hasher.ErrInvalidHashPrefix
		return
	}
	decodedLen := d.Encoding.DecodedLen(len(encodedHash) - len(d.Prefix))
	decoded := make([]byte, decodedLen)
	n, err := d.Encoding.Decode(decoded, encodedHash[len(d.Prefix):])
	if err != nil {
		return
	}
	r := bytes.NewReader(decoded[:n])
	saltLen, err := r.ReadByte()
	if err != nil {
		return
	}
	salt = make([]byte, int(saltLen))
	if _, err = r.Read(salt); err != nil {
		return
	}
	hash = make([]byte, r.Len())
	_, err = r.Read(hash)
	return
}
