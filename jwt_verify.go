//
//
//

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

type Verify_t struct {
	key crypto.PublicKey
}

func NewVerifyCertPem(buf []byte) (res Verifier, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = ERROR_PEM_DECODE_FAILED
		return
	}
	return NewVerifyCertDer(block.Bytes)
}

func NewVerifyCertDer(buf []byte) (res Verifier, err error) {
	certificate, err := x509.ParseCertificate(buf)
	if err != nil {
		return
	}
	return Verify_t{key: certificate.PublicKey}, nil
}

func NewVerifyKeyPem(buf []byte) (res Verifier, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = ERROR_PEM_DECODE_FAILED
		return
	}
	return NewVerifyKeyDer(block.Bytes)
}

func NewVerifyKeyDer(buf []byte) (res Verifier, err error) {
	key, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return
	}
	return Verify_t{key: key}, err
}

func NewVerifyKey(key crypto.PublicKey) (res Verifier, err error) {
	return Verify_t{key: key}, nil
}

func (self Verify_t) Name() string {
	switch k := self.key.(type) {
	case ed25519.PublicKey:
		return "ED"
	case *rsa.PublicKey:
		return "RS"
	case *ecdsa.PublicKey:
		return "ES"
	default:
		return fmt.Sprintf("KEY NOT SUPPORTED: %T", k)
	}
}

func (self Verify_t) Verify(bits int64, message []byte, signature []byte) (ok bool) {
	switch k := self.key.(type) {
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, message, signature)
	case *rsa.PublicKey:
		res := SHA(bits)
		if ok = res.Available(); !ok {
			return
		}
		h := res.New()
		h.Write(message)
		if err := rsa.VerifyPKCS1v15(k, res, h.Sum(nil), signature); err != nil {
			return false
		}
	case *ecdsa.PublicKey:
		CurveBytes := (k.Params().BitSize + 7) / 8
		if len(signature) < 2*CurveBytes {
			return
		}
		r := big.NewInt(0).SetBytes(signature[:CurveBytes])
		s := big.NewInt(0).SetBytes(signature[CurveBytes:])
		res := SHA(bits)
		if ok = res.Available(); !ok {
			return
		}
		h := res.New()
		h.Write(message)
		ok = ecdsa.Verify(k, h.Sum(nil), r, s)
	}
	return
}
