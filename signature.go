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

type Signer interface {
	Name() string
	Sign(bits int64, message []byte) (signature []byte, err error)
}

type Verifier interface {
	Name() string
	Verify(bits int64, message []byte, signature []byte) (ok bool, err error)
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

func NewSignPem(buf []byte) (res Sign_t, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = fmt.Errorf("PEM DECODE FAILED")
		return
	}
	return NewSignDer(block.Bytes)
}

func NewSignDer(buf []byte) (res Sign_t, err error) {
	if res.key, err = x509.ParsePKCS8PrivateKey(buf); err != nil {
		res.key, err = x509.ParseECPrivateKey(buf)
	}
	return
}

func NewSignKey(key crypto.PrivateKey) (res Sign_t, err error) {
	res.key = key
	return
}

func (self *Sign_t) Name() string {
	switch k := self.key.(type) {
	case ed25519.PrivateKey:
		return "ED"
	case *rsa.PrivateKey:
		return "RS"
	case *ecdsa.PrivateKey:
		return "ES"
	default:
		return fmt.Sprintf("KEY NOT SUPPORTED: %T", k)
	}
}

func (self *Sign_t) Sign(bits int64, message []byte) (signature []byte, err error) {
	switch k := self.key.(type) {
	case ed25519.PrivateKey:
		signature, err = k.Sign(rand.Reader, message, crypto.Hash(0))
	case *rsa.PrivateKey:
		if res := SHA(bits); res.Available() {
			h := res.New()
			h.Write(message)
			signature, err = k.Sign(rand.Reader, h.Sum(nil), res)
		} else {
			err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
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
			err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
		}
	default:
		err = fmt.Errorf("KEY NOT SUPPORTED: %T", k)
	}
	return
}

type Verify_t struct {
	key crypto.PublicKey
}

func NewVerifyPem(buf []byte) (res Verify_t, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		err = fmt.Errorf("PEM DECODE FAILED")
		return
	}
	return NewVerifyDer(block.Bytes)
}

func NewVerifyDer(buf []byte) (res Verify_t, err error) {
	var certificate *x509.Certificate
	if certificate, err = x509.ParseCertificate(buf); err != nil {
		return
	}
	res.key = certificate.PublicKey
	return
}

func NewVerifyKey(key crypto.PublicKey) (res Verify_t, err error) {
	res.key = key
	return
}

func (self *Verify_t) Name() string {
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

func (self *Verify_t) Verify(bits int64, message []byte, signature []byte) (ok bool, err error) {
	switch k := self.key.(type) {
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, message, signature)
	case *rsa.PublicKey:
		if res := SHA(bits); res.Available() {
			h := res.New()
			h.Write(message)
			if err = rsa.VerifyPKCS1v15(k, res, h.Sum(nil), signature); err == nil {
				ok = true
			}
		} else {
			err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
		}
	case *ecdsa.PublicKey:
		CurveBytes := (k.Params().BitSize + 7) / 8
		if len(signature) < 2*CurveBytes {
			return false, fmt.Errorf("SIGNATURE LENGTH")
		}
		r := big.NewInt(0).SetBytes(signature[:CurveBytes])
		s := big.NewInt(0).SetBytes(signature[CurveBytes:])
		if res := SHA(bits); res.Available() {
			h := res.New()
			h.Write(message)
			ok = ecdsa.Verify(k, h.Sum(nil), r, s)
		} else {
			err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
		}
	default:
		err = fmt.Errorf("KEY NOT SUPPORTED: %T", k)
	}
	return
}

type Hmac_t struct {
	key []byte
}

func NewHmacKey(key []byte) (res Hmac_t, err error) {
	res.key = append(res.key, key...)
	return
}

func (self *Hmac_t) Name() string {
	return "HS"
}

func (self *Hmac_t) Sign(bits int64, message []byte) (signature []byte, err error) {
	if res := SHA(bits); res.Available() {
		h := hmac.New(res.New, self.key)
		h.Write(message)
		signature = h.Sum(nil)
	} else {
		err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
	}
	return
}

func (self *Hmac_t) Verify(bits int64, message []byte, signature []byte) (ok bool, err error) {
	if res := SHA(bits); res.Available() {
		h := hmac.New(res.New, self.key)
		h.Write(message)
		ok = hmac.Equal(h.Sum(nil), signature)
	} else {
		err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
	}
	return
}
