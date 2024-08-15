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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

type Verify_ed25519_t struct {
	key ed25519.PublicKey
}

type Verify_rsa_t struct {
	key *rsa.PublicKey
}

type Verify_ecdsa_t struct {
	key *ecdsa.PublicKey
}

type Verify_dsa_t struct {
	key *dsa.PublicKey
}

type Verify_ecdh_t struct {
	key *ecdh.PublicKey
}

func NewVerifyCertPem(buf []byte) (res Verifier, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = ERROR_VERIFY_PEM_DECODE_FAILED
		return
	}
	return NewVerifyCertDer(block.Bytes)
}

func NewVerifyCertDer(buf []byte) (res Verifier, err error) {
	certificate, err := x509.ParseCertificate(buf)
	if err != nil {
		return
	}
	return NewVerifyKey(certificate.PublicKey)
}

func NewVerifyKeyPem(buf []byte) (res Verifier, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = ERROR_VERIFY_PEM_DECODE_FAILED
		return
	}
	return NewVerifyKeyDer(block.Bytes)
}

func NewVerifyKeyDer(buf []byte) (res Verifier, err error) {
	key, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return
	}
	return NewVerifyKey(key)
}

func NewVerifyKey(key crypto.PublicKey) (res Verifier, err error) {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return &Verify_ed25519_t{key: k}, nil
	case *rsa.PublicKey:
		return &Verify_rsa_t{key: k}, nil
	case *ecdsa.PublicKey:
		return &Verify_ecdsa_t{key: k}, nil
	case *dsa.PublicKey:
		return &Verify_dsa_t{key: k}, nil
	case *ecdh.PublicKey:
		return &Verify_ecdh_t{key: k}, nil
	default:
		return nil, ERROR_VERIFY_KEY_NOT_SUPPORTED
	}
}

func (self *Verify_ed25519_t) Name() string {
	return "ED"
}

func (self *Verify_rsa_t) Name() string {
	return "RS"
}

func (self *Verify_ecdsa_t) Name() string {
	return "ES"
}

func (self *Verify_dsa_t) Name() string {
	return "DS"
}

func (self *Verify_ecdh_t) Name() string {
	return "EC"
}

func (self *Verify_ed25519_t) Verify(bits int64, message []byte, signature []byte) bool {
	return ed25519.Verify(self.key, message, signature)
}

func (self *Verify_rsa_t) Verify(bits int64, message []byte, signature []byte) (ok bool) {
	res := SHA(bits)
	if ok = res.Available(); !ok {
		return
	}
	h := res.New()
	h.Write(message)
	if rsa.VerifyPKCS1v15(self.key, res, h.Sum(nil), signature) != nil {
		return false
	}
	return
}

func (self Verify_ecdsa_t) Verify(bits int64, message []byte, signature []byte) (ok bool) {
	res := SHA(bits)
	if ok = res.Available(); !ok {
		return
	}
	CurveBytes := (self.key.Params().BitSize + 7) / 8
	if len(signature) < 2*CurveBytes {
		return
	}
	r := big.NewInt(0).SetBytes(signature[:CurveBytes])
	s := big.NewInt(0).SetBytes(signature[CurveBytes:])
	h := res.New()
	h.Write(message)
	return ecdsa.Verify(self.key, h.Sum(nil), r, s)
}

func (self *Verify_dsa_t) Verify(bits int64, message []byte, signature []byte) (ok bool) {
	res := SHA(bits)
	if ok = res.Available(); !ok {
		return
	}
	CurveBytes := (self.key.Q.BitLen() + 7) / 8
	if len(signature) < 2*CurveBytes {
		return
	}
	r := big.NewInt(0).SetBytes(signature[:CurveBytes])
	s := big.NewInt(0).SetBytes(signature[CurveBytes:])
	h := res.New()
	h.Write(message)
	return dsa.Verify(self.key, h.Sum(nil), r, s)
}

func (self *Verify_ecdh_t) Verify(bits int64, message []byte, signature []byte) (ok bool) {
	return
}
