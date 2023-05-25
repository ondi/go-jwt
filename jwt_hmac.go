//
//
//

package jwt

import "crypto/hmac"

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
		err = ERROR_HASH_NOT_AVAILABLE
	}
	return
}

func (self Hmac_t) Verify(bits int64, message []byte, signature []byte) (err error) {
	if res := SHA(bits); res.Available() {
		h := hmac.New(res.New, self.key)
		h.Write(message)
		if !hmac.Equal(h.Sum(nil), signature) {
			err = ERROR_VERIFICATION_FAILED
		}
	} else {
		err = ERROR_HASH_NOT_AVAILABLE
	}
	return
}
