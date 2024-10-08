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
	AlgKey_t
	key ed25519.PublicKey
}

type Verify_rsa_t struct {
	AlgKey_t
	key *rsa.PublicKey
}

type Verify_ecdsa_t struct {
	AlgKey_t
	key *ecdsa.PublicKey
}

type Verify_dsa_t struct {
	AlgKey_t
	key *dsa.PublicKey
}

type Verify_ecdh_t struct {
	AlgKey_t
	key *ecdh.PublicKey
}

func NewVerifyCertPem(id string, buf []byte) (res Verifier, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = ERROR_VERIFY_PEM_DECODE_FAILED
		return
	}
	return NewVerifyCertDer(id, block.Bytes)
}

func NewVerifyCertDer(id string, buf []byte) (res Verifier, err error) {
	certificate, err := x509.ParseCertificate(buf)
	if err != nil {
		return
	}
	return NewVerifyKey(id, certificate.PublicKey)
}

func NewVerifyKeyPem(id string, buf []byte) (res Verifier, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = ERROR_VERIFY_PEM_DECODE_FAILED
		return
	}
	return NewVerifyKeyDer(id, block.Bytes)
}

func NewVerifyKeyDer(id string, buf []byte) (res Verifier, err error) {
	key, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return
	}
	return NewVerifyKey(id, key)
}

func NewVerifyKey(id string, key crypto.PublicKey) (res Verifier, err error) {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return &Verify_ed25519_t{AlgKey_t: AlgKey_t{id: id, name: "ED"}, key: k}, nil
	case *rsa.PublicKey:
		return &Verify_rsa_t{AlgKey_t: AlgKey_t{id: id, name: "RS"}, key: k}, nil
	case *ecdsa.PublicKey:
		return &Verify_ecdsa_t{AlgKey_t: AlgKey_t{id: id, name: "ES"}, key: k}, nil
	case *dsa.PublicKey:
		return &Verify_dsa_t{AlgKey_t: AlgKey_t{id: id, name: "DS"}, key: k}, nil
	case *ecdh.PublicKey:
		return &Verify_ecdh_t{AlgKey_t: AlgKey_t{id: id, name: "EC"}, key: k}, nil
	default:
		return nil, ERROR_VERIFY_KEY_NOT_SUPPORTED
	}
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
