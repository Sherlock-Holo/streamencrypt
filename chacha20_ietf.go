package streamencrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/Yawning/chacha20"
)

type ChaCha20Ietf struct {
	key    []byte
	iv     []byte
	cipher *chacha20.Cipher
	reader cipher.StreamReader
	writer cipher.StreamWriter
}

func (c *ChaCha20Ietf) IV() []byte {
	return c.iv
}

func (c *ChaCha20Ietf) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *ChaCha20Ietf) Write(b []byte) (n int, err error) {
	return c.writer.Write(b)
}

func (c *ChaCha20Ietf) InitReader(r io.Reader) {
	c.reader.R = r
	c.reader.S = c.cipher
}

func (c *ChaCha20Ietf) InitWriter(w io.Writer) {
	c.writer.W = w
	c.writer.S = c.cipher
}

func NewChacha20Ietf(key, iv []byte) (Cipher, error) {
	if iv == nil {
		iv = make([]byte, 12)
		rand.Read(iv)
	}

	ciph, err := chacha20.NewCipher(key, iv)
	if err != nil {
		return nil, err
	}

	return &ChaCha20Ietf{
		key:    key,
		iv:     iv,
		cipher: ciph,
	}, nil
}
