//
//
//

package jwt

import (
	"io/ioutil"
	"testing"
	"time"

	"gotest.tools/assert"
)

func SignVerify(t *testing.T, key string, cert string) {
	hash_bits := 256

	ts := time.Now()
	payload := map[string]interface{}{}
	// issued at
	payload["iat"] = ts.Unix()
	// not before
	payload["nbf"] = ts.Unix()
	// expiration
	payload["exp"] = ts.Add(15 * time.Second).Unix()
	// data
	payload["lalala"] = "bububu"

	var s Sign_t
	buf, err := ioutil.ReadFile(key)
	assert.NilError(t, err, "READ KEY")
	err = s.LoadKeyPem(buf)
	assert.NilError(t, err, "LOAD KEY")
	token, err := Sign(&s, hash_bits, payload)
	assert.NilError(t, err, "JWT CREATE")
	t.Logf("SignVerify: key=%v, alg=%v, out=%s", key, s.Name(hash_bits), token.Bytes())

	var v Verify_t
	buf, err = ioutil.ReadFile(cert)
	assert.NilError(t, err, "READ CERT")
	err = v.LoadCertPem(buf)
	assert.NilError(t, err, "LOAD CERT")
	payload, ok, err := Verify(&v, token.Bytes())
	assert.NilError(t, err, "VERIFY ERROR")
	assert.Assert(t, ok, "VERIFY")
	err = Validate(payload)
	assert.NilError(t, err, "VALIDATE")
	t.Logf("PAYLOAD: %v", payload)
}

func Test01(t *testing.T) {
	SignVerify(t, "test01.pem", "test01.crt")
}

func Test02(t *testing.T) {
	SignVerify(t, "test02.pem", "test02.crt")
}

func Test03(t *testing.T) {
	SignVerify(t, "test03.pem", "test03.crt")
}

func Test04(t *testing.T) {
	SignVerify(t, "test04.pem", "test04.crt")
}

func Test05(t *testing.T) {
	SignVerify(t, "test05.pem", "test05.crt")
}

func Test06(t *testing.T) {
	SignVerify(t, "test06.pem", "test06.crt")
}

func Test07(t *testing.T) {
	SignVerify(t, "test07.pem", "test07.crt")
}

func Test08(t *testing.T) {
	SignVerify(t, "test08.pem", "test08.crt")
}

func Test09(t *testing.T) {
	SignVerify(t, "test09.pem", "test09.crt")
}

func Test10(t *testing.T) {
	hash_bits := 256

	ts := time.Now()
	payload := map[string]interface{}{}
	// issued at
	payload["iat"] = ts.Unix()
	// not before
	payload["nbf"] = ts.Unix()
	// expiration
	payload["exp"] = ts.Add(15 * time.Second).Unix()
	// data
	payload["lalala"] = "bububu"

	var h Hmac_t
	buf, err := ioutil.ReadFile("test10.hmac")
	assert.NilError(t, err, "READ KEY")
	err = h.LoadKeyPem(buf)
	assert.NilError(t, err, "LOAD KEY")
	token, err := Sign(&h, hash_bits, payload)
	assert.NilError(t, err, "JWT CREATE")
	t.Logf("Test10: key=%v, alg=%v, out=%s", "test10.hmac", h.Name(hash_bits), token.Bytes())

	payload, ok, err := Verify(&h, token.Bytes())
	assert.NilError(t, err, "VERIFY ERROR")
	assert.Assert(t, ok, "VERIFY")
	err = Validate(payload)
	assert.NilError(t, err, "VALIDATE")
	t.Logf("PAYLOAD: %v", payload)
}
