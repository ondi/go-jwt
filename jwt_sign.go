//
//
//

package jwt

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type Sign_ed25519_t struct {
	key ed25519.PrivateKey
}

type Sign_rsa_t struct {
	key *rsa.PrivateKey
}

type Sign_ecdsa_t struct {
	key *ecdsa.PrivateKey
}

type Sign_dsa_t struct {
	key *dsa.PrivateKey
}

type Sign_ecdh_t struct {
	key *ecdh.PrivateKey
}

func NewSignPem(buf []byte) (res Signer, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = ERROR_VERIFY_PEM_DECODE_FAILED
		return
	}
	return NewSignDer(block.Bytes)
}

func NewSignDer(buf []byte) (Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(buf)
	if err != nil {
		key, err = x509.ParseECPrivateKey(buf)
		if err != nil {
			return nil, err
		}
	}
	return NewSignKey(key)
}

func NewSignKey(key crypto.PrivateKey) (Signer, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return &Sign_ed25519_t{key: k}, nil
	case *rsa.PrivateKey:
		return &Sign_rsa_t{key: k}, nil
	case *ecdsa.PrivateKey:
		return &Sign_ecdsa_t{key: k}, nil
	case *dsa.PrivateKey:
		return &Sign_dsa_t{key: k}, nil
	case *ecdh.PrivateKey:
		return &Sign_ecdh_t{key: k}, nil
	default:
		return nil, ERROR_VERIFY_KEY_NOT_SUPPORTED
	}
}

func (self *Sign_ed25519_t) Name() string {
	return "ED"
}

func (self *Sign_rsa_t) Name() string {
	return "RS"
}

func (self *Sign_ecdsa_t) Name() string {
	return "ES"
}

func (self *Sign_dsa_t) Name() string {
	return "DS"
}

func (self *Sign_ecdh_t) Name() string {
	return "EC"
}

func (self *Sign_ed25519_t) Sign(bits int64, message []byte) ([]byte, error) {
	return self.key.Sign(rand.Reader, message, crypto.Hash(0))
}

func (self *Sign_rsa_t) Sign(bits int64, message []byte) ([]byte, error) {
	res := SHA(bits)
	if !res.Available() {
		return nil, ERROR_VERIFY_HASH_NOT_AVAILABLE
	}
	h := res.New()
	h.Write(message)
	return self.key.Sign(rand.Reader, h.Sum(nil), res)
}

func (self *Sign_ecdsa_t) Sign(bits int64, message []byte) (signature []byte, err error) {
	res := SHA(bits)
	if !res.Available() {
		return nil, ERROR_VERIFY_HASH_NOT_AVAILABLE
	}
	h := res.New()
	h.Write(message)
	r, s, err := ecdsa.Sign(rand.Reader, self.key, h.Sum(nil))
	if err != nil {
		return
	}
	CurveBytes := (self.key.Params().BitSize + 7) / 8
	for i := 0; i < CurveBytes-len(r.Bytes()); i++ {
		signature = append(signature, 0)
	}
	signature = append(signature, r.Bytes()...)
	for i := 0; i < CurveBytes-len(s.Bytes()); i++ {
		signature = append(signature, 0)
	}
	signature = append(signature, s.Bytes()...)
	return
}

func (self *Sign_dsa_t) Sign(bits int64, message []byte) (signature []byte, err error) {
	res := SHA(bits)
	if !res.Available() {
		return nil, ERROR_VERIFY_HASH_NOT_AVAILABLE
	}
	h := res.New()
	h.Write(message)
	r, s, err := dsa.Sign(rand.Reader, self.key, h.Sum(nil))
	if err != nil {
		return
	}
	CurveBytes := (self.key.Q.BitLen() + 7) / 8
	for i := 0; i < CurveBytes-len(r.Bytes()); i++ {
		signature = append(signature, 0)
	}
	signature = append(signature, r.Bytes()...)
	for i := 0; i < CurveBytes-len(s.Bytes()); i++ {
		signature = append(signature, 0)
	}
	signature = append(signature, s.Bytes()...)
	return
}

func (self *Sign_ecdh_t) Sign(bits int64, message []byte) (signature []byte, err error) {
	return nil, ERROR_VERIFY_KEY_NOT_SUPPORTED
}
