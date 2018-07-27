package streamencrypt

import "io"

type Type int

const (
	CHACHA20_IETF Type = iota
)

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

var Ciphers = map[Type]CipherInfo{
	CHACHA20_IETF: {32, 12, NewChacha20Ietf},
}
