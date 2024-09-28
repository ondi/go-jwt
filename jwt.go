//
//
//

package jwt

import "crypto"

type AlgIdent interface {
	AlgId() string
	AlgName() string
}

type AlgSign interface {
	Sign(bits int64, message []byte) (signature []byte, err error)
}

type AlgVerify interface {
	Verify(bits int64, message []byte, signature []byte) (ok bool)
}

type Signer interface {
	AlgIdent
	AlgSign
}

type Verifier interface {
	AlgIdent
	AlgVerify
}

type Hmac interface {
	AlgIdent
	AlgSign
	AlgVerify
}

type AlgIdent_t struct {
	id   string
	name string
}

func (self *AlgIdent_t) AlgId() string {
	return self.id
}

func (self *AlgIdent_t) AlgName() string {
	return self.name
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
