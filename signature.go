//
//
//

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

var VERIFICATION_FAILED = fmt.Errorf("VERIFICATION FAILED")
var PEM_DECODE_FAILED = fmt.Errorf("PEM DECODE FAILED")
var HASH_NOT_AVAILABLE = fmt.Errorf("HASH NOT AVAILABLE")
var KEY_NOT_SUPPORTED = fmt.Errorf("KEY NOT SUPPORTED:")
var SIGNATURE_LENGTH = fmt.Errorf("SIGNATURE LENGTH")

type AName interface {
	Name() string
}

type ASign interface {
	Sign(bits int64, message []byte) (signature []byte, err error)
}

type AVerify interface {
	Verify(bits int64, message []byte, signature []byte) (err error)
}

type Signer interface {
	AName
	ASign
}

type Verifier interface {
	AName
	AVerify
}

type Hmac interface {
	AName
	ASign
	AVerify
}

func SHA(bits int64) (res crypto.Hash) {
	if bits <= 224 {
		res = crypto.SHA224
	} else if bits <= 256 {
		res = crypto.SHA256
	} else if bits <= 384 {
		res = crypto.SHA384
	} else /*if bits <= 512*/ {
		res = crypto.SHA512
	}
	return
}

type Sign_t struct {
	key crypto.PrivateKey
}

func NewSignPem(buf []byte) (res Signer, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = PEM_DECODE_FAILED
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
		if res := SHA(bits); res.Available() {
			h := res.New()
			h.Write(message)
			signature, err = k.Sign(rand.Reader, h.Sum(nil), res)
		} else {
			err = HASH_NOT_AVAILABLE
		}
	case *ecdsa.PrivateKey:
		if res := SHA(bits); res.Available() {
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
		} else {
			err = HASH_NOT_AVAILABLE
		}
	default:
		err = KEY_NOT_SUPPORTED
	}
	return
}

type Verify_t struct {
	key crypto.PublicKey
}

func NewVerifyCertPem(buf []byte) (res Verifier, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = PEM_DECODE_FAILED
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
		err = PEM_DECODE_FAILED
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

func (self Verify_t) Verify(bits int64, message []byte, signature []byte) (err error) {
	switch k := self.key.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, message, signature) {
			err = VERIFICATION_FAILED
		}
	case *rsa.PublicKey:
		if res := SHA(bits); res.Available() {
			h := res.New()
			h.Write(message)
			err = rsa.VerifyPKCS1v15(k, res, h.Sum(nil), signature)
		} else {
			err = HASH_NOT_AVAILABLE
		}
	case *ecdsa.PublicKey:
		CurveBytes := (k.Params().BitSize + 7) / 8
		if len(signature) < 2*CurveBytes {
			return SIGNATURE_LENGTH
		}
		r := big.NewInt(0).SetBytes(signature[:CurveBytes])
		s := big.NewInt(0).SetBytes(signature[CurveBytes:])
		if res := SHA(bits); res.Available() {
			h := res.New()
			h.Write(message)
			if !ecdsa.Verify(k, h.Sum(nil), r, s) {
				err = VERIFICATION_FAILED
			}
		} else {
			err = HASH_NOT_AVAILABLE
		}
	default:
		err = KEY_NOT_SUPPORTED
	}
	return
}

type Hmac_t struct {
	key []byte
}

func NewHmacKey(key []byte) (res Hmac, err error) {
	return Hmac_t{key: append([]byte{}, key...)}, nil
}

func (self Hmac_t) Name() string {
	return "HS"
}

func (self Hmac_t) Sign(bits int64, message []byte) (signature []byte, err error) {
	if res := SHA(bits); res.Available() {
		h := hmac.New(res.New, self.key)
		h.Write(message)
		signature = h.Sum(nil)
	} else {
		err = HASH_NOT_AVAILABLE
	}
	return
}

func (self Hmac_t) Verify(bits int64, message []byte, signature []byte) (err error) {
	if res := SHA(bits); res.Available() {
		h := hmac.New(res.New, self.key)
		h.Write(message)
		if !hmac.Equal(h.Sum(nil), signature) {
			err = VERIFICATION_FAILED
		}
	} else {
		err = HASH_NOT_AVAILABLE
	}
	return
}
