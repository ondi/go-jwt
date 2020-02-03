//
//
//

package jwt

import "fmt"
import "crypto"
import "crypto/rsa"
import "crypto/ecdsa"
import "crypto/ed25519"
import "crypto/rand"
import "crypto/x509"
import "encoding/pem"
import "io/ioutil"
import "math/big"

func SHA(bits int) (crypto.Hash, bool) {
	var res crypto.Hash
	if bits <= 224 {
		res = crypto.SHA224
	} else if bits <= 256 {
		res = crypto.SHA256
	} else if bits <= 384 {
		res = crypto.SHA384
	} else /*if bits <= 512*/ {
		res = crypto.SHA512
	}
	return res, res.Available()
}

type Sign_t struct {
	key crypto.PrivateKey
}

func (self * Sign_t) LoadKeyPem(file string) (err error) {
	var buf []byte
	if buf, err = ioutil.ReadFile(file); err != nil {
		return
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return fmt.Errorf("PEM decode failed")
	}
	if self.key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		self.key, err = x509.ParseECPrivateKey(block.Bytes)
	}
	return
}

func (self * Sign_t) LoadKeyDer(file string) (err error) {
	var buf []byte
	if buf, err = ioutil.ReadFile(file); err != nil {
		return
	}
	if self.key, err = x509.ParsePKCS8PrivateKey(buf); err != nil {
		self.key, err = x509.ParseECPrivateKey(buf)
	}
	return
}

func (self * Sign_t) Name(bits int) string {
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

func (self * Sign_t) Sign(bits int, message []byte) (signature []byte, err error) {
	switch k := self.key.(type) {
	case ed25519.PrivateKey:
		signature, err = k.Sign(rand.Reader, message, crypto.Hash(0))
	case *rsa.PrivateKey:
		if res, ok := SHA(bits); ok {
			h := res.New()
			h.Write(message)
			signature, err = k.Sign(rand.Reader, h.Sum(nil), res)
		} else {
			err = fmt.Errorf("HASH NOT AVAILABLE %v", bits)
		}
	case *ecdsa.PrivateKey:
		if res, ok := SHA(bits); ok {
			h := res.New()
			h.Write(message)
			var r, s * big.Int
			if r, s, err = ecdsa.Sign(rand.Reader, k, h.Sum(nil)); err != nil {
				return
			}
			CurveBytes := (k.Params().BitSize + 7) / 8
			for i := 0; i < CurveBytes - len(r.Bytes()); i++ {
				signature = append(signature, 0)
			}
			signature = append(signature, r.Bytes()...)
			for i := 0; i < CurveBytes - len(s.Bytes()); i++ {
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

func (self * Verify_t) LoadCertPem(file string) (err error) {
	var buf []byte
	if buf, err = ioutil.ReadFile(file); err != nil {
		return
	}
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

func (self * Verify_t) LoadCertDer(file string) (err error) {
	var buf []byte
	if buf, err = ioutil.ReadFile(file); err != nil {
		return
	}
	var certificate *x509.Certificate
	if certificate, err = x509.ParseCertificate(buf); err != nil {
		return
	}
	self.key = certificate.PublicKey
	return
}

func (self * Verify_t) Verify(bits int, message []byte, signature []byte) (ok bool, err error) {
	switch k := self.key.(type) {
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, message, signature)
	case *rsa.PublicKey:
		if res, ok := SHA(bits); ok {
			h := res.New()
			h.Write(message)
			if err = rsa.VerifyPKCS1v15(k, res, h.Sum(nil), signature); err == nil {
				return true, nil
			}
		}
	case *ecdsa.PublicKey:
		CurveBytes := (k.Params().BitSize + 7) / 8
		if len(signature) < 2 * CurveBytes {
			return false, fmt.Errorf("SIGNATURE LENGTH")
		}
		r := big.NewInt(0).SetBytes(signature[:CurveBytes])
		s := big.NewInt(0).SetBytes(signature[CurveBytes:])
		if res, ok2 := SHA(bits); ok2 {
			h := res.New()
			h.Write(message)
			ok = ecdsa.Verify(k, h.Sum(nil), r, s)
		}
	default:
		err = fmt.Errorf("KEY NOT SUPPORTED: %T", k)
	}
	return
}
