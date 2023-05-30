//
//
//

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

type Sign_t struct {
	key crypto.PrivateKey
}

func NewSignPem(buf []byte) (res Signer, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = ERROR_PEM_DECODE_FAILED
		return
	}
	return NewSignDer(block.Bytes)
}

func NewSignDer(buf []byte) (Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(buf)
	if err != nil {
		key, err = x509.ParseECPrivateKey(buf)
	}
	return Sign_t{key: key}, err
}

func NewSignKey(key crypto.PrivateKey) (Signer, error) {
	return Sign_t{key: key}, nil
}

func (self Sign_t) Name() string {
	switch self.key.(type) {
	case ed25519.PrivateKey:
		return "ED"
	case *rsa.PrivateKey:
		return "RS"
	case *ecdsa.PrivateKey:
		return "ES"
	default:
		return "KEY NOT SUPPORTED"
	}
}

func (self Sign_t) Sign(bits int64, message []byte) (signature []byte, err error) {
	switch k := self.key.(type) {
	case ed25519.PrivateKey:
		signature, err = k.Sign(rand.Reader, message, crypto.Hash(0))
	case *rsa.PrivateKey:
		res := SHA(bits)
		if !res.Available() {
			return nil, ERROR_HASH_NOT_AVAILABLE
		}
		h := res.New()
		h.Write(message)
		signature, err = k.Sign(rand.Reader, h.Sum(nil), res)
	case *ecdsa.PrivateKey:
		res := SHA(bits)
		if !res.Available() {
			return nil, ERROR_HASH_NOT_AVAILABLE
		}
		h := res.New()
		h.Write(message)
		var r, s *big.Int
		if r, s, err = ecdsa.Sign(rand.Reader, k, h.Sum(nil)); err != nil {
			return
		}
		CurveBytes := (k.Params().BitSize + 7) / 8
		for i := 0; i < CurveBytes-len(r.Bytes()); i++ {
			signature = append(signature, 0)
		}
		signature = append(signature, r.Bytes()...)
		for i := 0; i < CurveBytes-len(s.Bytes()); i++ {
			signature = append(signature, 0)
		}
		signature = append(signature, s.Bytes()...)
	default:
		err = ERROR_KEY_NOT_SUPPORTED
	}
	return
}
