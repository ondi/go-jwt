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
	LoadKeyPem(buf []byte) (err error)
	LoadKeyDer(buf []byte) (err error)
	Name(bits int) string
	Sign(bits int, message []byte) (signature []byte, err error)
}

type Verifier interface {
	LoadCertPem(buf []byte) (err error)
	LoadCertDer(buf []byte) (err error)
	Name(bits int) string
	Verify(bits int, message []byte, signature []byte) (ok bool, err error)
}

func SHA(bits int) (res crypto.Hash) {
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

func (self *Sign_t) LoadKeyPem(buf []byte) (err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		return fmt.Errorf("PEM decode failed")
	}
	if self.key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		self.key, err = x509.ParseECPrivateKey(block.Bytes)
	}
	return
}

func (self *Sign_t) LoadKeyDer(buf []byte) (err error) {
	if self.key, err = x509.ParsePKCS8PrivateKey(buf); err != nil {
		self.key, err = x509.ParseECPrivateKey(buf)
	}
	return
}

func (self *Sign_t) Name(bits int) string {
	switch k := self.key.(type) {
	case ed25519.PrivateKey:
		return "ED25519"
	case *rsa.PrivateKey:
		return fmt.Sprintf("RS%d", bits)
	case *ecdsa.PrivateKey:
		return fmt.Sprintf("ES%d", bits)
	default:
		return fmt.Sprintf("KEY NOT SUPPORTED: %T", k)
	}
}

func (self *Sign_t) Sign(bits int, message []byte) (signature []byte, err error) {
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

func (self *Verify_t) LoadCertPem(buf []byte) (err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		return fmt.Errorf("PEM decode failed")
	}
	var certificate *x509.Certificate
	if certificate, err = x509.ParseCertificate(block.Bytes); err != nil {
		return
	}
	self.key = certificate.PublicKey
	return
}

func (self *Verify_t) LoadCertDer(buf []byte) (err error) {
	var certificate *x509.Certificate
	if certificate, err = x509.ParseCertificate(buf); err != nil {
		return
	}
	self.key = certificate.PublicKey
	return
}

func (self *Verify_t) Name(bits int) string {
	switch k := self.key.(type) {
	case ed25519.PublicKey:
		return "ED25519"
	case *rsa.PublicKey:
		return fmt.Sprintf("RS%d", bits)
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ES%d", bits)
	default:
		return fmt.Sprintf("KEY NOT SUPPORTED: %T", k)
	}
}

func (self *Verify_t) Verify(bits int, message []byte, signature []byte) (ok bool, err error) {
	switch k := self.key.(type) {
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, message, signature)
	case *rsa.PublicKey:
		if res := SHA(bits); res.Available() {
			h := res.New()
			h.Write(message)
			if err = rsa.VerifyPKCS1v15(k, res, h.Sum(nil), signature); err == nil {
				return true, nil
			}
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
		}
	default:
		err = fmt.Errorf("KEY NOT SUPPORTED: %T", k)
	}
	return
}

type Hmac_t struct {
	key []byte
}

func (self *Hmac_t) LoadKeyPem(buf []byte) (err error) {
	self.key = append([]byte{}, buf...)
	return
}

func (self *Hmac_t) LoadKeyDer(buf []byte) (err error) {
	return self.LoadKeyPem(buf)
}

func (self *Hmac_t) LoadCertPem(buf []byte) (err error) {
	return self.LoadKeyPem(buf)
}

func (self *Hmac_t) LoadCertDer(buf []byte) (err error) {
	return self.LoadKeyPem(buf)
}

func (self *Hmac_t) Name(bits int) string {
	return fmt.Sprintf("HS%d", bits)
}

func (self *Hmac_t) Sign(bits int, message []byte) (signature []byte, err error) {
	if res := SHA(bits); res.Available() {
		h := hmac.New(res.New, self.key)
		h.Write(message)
		signature = h.Sum(nil)
	} else {
		err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
	}
	return
}

func (self *Hmac_t) Verify(bits int, message []byte, signature []byte) (ok bool, err error) {
	if res := SHA(bits); res.Available() {
		h := hmac.New(res.New, self.key)
		h.Write(message)
		ok = hmac.Equal(h.Sum(nil), signature)
	} else {
		err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
	}
	return
}
