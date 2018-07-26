package streamencrypt

import "io"

type Cipher interface {
	IV() []byte
	InitReader(r io.Reader)
	InitWriter(w io.Writer)

	io.ReadWriter
}

type CipherInfo struct {
	KeyLen    int
	IVLen     int
	NewCipher func(key, iv []byte) (Cipher, error)
}

var Ciphers = map[string]CipherInfo{
	"ChaCha20-ietf": {32, 12, NewChacha20Ietf},
}
