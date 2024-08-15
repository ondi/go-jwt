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
	res := SHA(bits)
	if !res.Available() {
		err = ERROR_VERIFY_HASH_NOT_AVAILABLE
		return
	}
	h := hmac.New(res.New, self.key)
	h.Write(message)
	signature = h.Sum(nil)
	return
}

func (self Hmac_t) Verify(bits int64, message []byte, signature []byte) (ok bool) {
	res := SHA(bits)
	if ok = res.Available(); !ok {
		return
	}
	h := hmac.New(res.New, self.key)
	h.Write(message)
	ok = hmac.Equal(h.Sum(nil), signature)
	return
}
