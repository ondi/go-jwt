//
//
//

package jwt

import "crypto"

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
