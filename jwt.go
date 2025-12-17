//
//
//

package jwt

import "crypto"

type AlgKey interface {
	KeyId() string
	AlgName() string
}

type AlgSign interface {
	Sign(bits int64, message []byte) (signature []byte, err error)
	Public() crypto.PublicKey
}

type AlgVerify interface {
	Verify(bits int64, message []byte, signature []byte) (ok bool)
}

type Signer interface {
	AlgKey
	AlgSign
}

type Verifier interface {
	AlgKey
	AlgVerify
}

type Hmac interface {
	AlgKey
	AlgSign
	AlgVerify
}

type AlgKey_t struct {
	id   string
	name string
}

func (self *AlgKey_t) KeyId() string {
	return self.id
}

func (self *AlgKey_t) AlgName() string {
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
