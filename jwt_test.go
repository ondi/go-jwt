//
//
//

package jwt

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"gotest.tools/assert"
)

var hmac_file = "test20.hmac"

func SignVerify(t *testing.T, key string, cert string) {
	hash_bits := int64(256)

	ts := time.Now()
	input := fmt.Sprintf(`{
"iat":%d,
"nbf":%d,
"exp":%d,
"lalala":"bububu"
}`,
		ts.Unix(),
		ts.Unix(),
		ts.Add(15*time.Second).Unix(),
	)

	var s Signer
	buf, err := os.ReadFile(key)
	assert.NilError(t, err, "READ KEY")
	s, err = NewSignPem(buf)
	assert.NilError(t, err, "LOAD KEY")
	var token bytes.Buffer
	err = Sign(s, hash_bits, []byte(input), &token)
	assert.NilError(t, err, "JWT CREATE")
	t.Logf("Sign: key=%v, alg=%v, bits=%v, out=%s", key, s.Name(), hash_bits, token.Bytes())

	var v Verifier
	buf, err = os.ReadFile(cert)
	assert.NilError(t, err, "READ CERT")
	v, err = NewVerifyCertPem(buf)
	assert.NilError(t, err, "LOAD CERT")
	_, bits, _, payload, signature, err := Parse(token.Bytes())
	assert.NilError(t, err)
	ok := Verify(v, bits, signature, token.Bytes())
	assert.Assert(t, ok, "VERIFY ERROR")
	t.Logf("Verify: cert=%v, alg=%v, bits=%v, payload=%v", cert, v.Name(), hash_bits, payload)
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

// TODO
// func Test10(t *testing.T) {
// 	SignVerify(t, "test10.pem", "test10.crt")
// }

func Test20(t *testing.T) {
	hash_bits := int64(256)

	ts := time.Now()
	input := fmt.Sprintf(`{
"iat":%d,
"nbf":%d,
"exp":%d,
"lalala":"bububu"
}`,
		ts.Unix(),
		ts.Unix(),
		ts.Add(15*time.Second).Unix(),
	)

	var h Hmac
	buf, err := os.ReadFile(hmac_file)
	assert.NilError(t, err, "READ KEY")
	h, err = NewHmacKey(buf)
	assert.NilError(t, err, "LOAD KEY")
	var token bytes.Buffer
	err = Sign(h, hash_bits, []byte(input), &token)
	assert.NilError(t, err, "JWT CREATE")
	t.Logf("Sign: key=%v, alg=%v, bits=%v, out=%s", hmac_file, h.Name(), hash_bits, token.Bytes())

	_, bits, _, payload, signature, err := Parse(token.Bytes())
	assert.NilError(t, err)
	ok := Verify(h, bits, signature, token.Bytes())
	assert.Assert(t, ok, "VERIFY ERROR")
	t.Logf("Verify: cert=%v, alg=%v, bits=%v, payload=%v", hmac_file, h.Name(), hash_bits, payload)
}

func Test21(t *testing.T) {
	var err error
	_, _, _, _, _, err = Parse(nil)
	assert.Error(t, err, "FORMAT ERROR")
	_, _, _, _, _, err = Parse([]byte{})
	assert.Error(t, err, "FORMAT ERROR")
	_, _, _, _, _, err = Parse([]byte("eyJhbGciOiJFRDI1NTE5In0K"))
	assert.Error(t, err, "FORMAT ERROR")
	_, _, _, _, _, err = Parse([]byte("eyJhbGciOiJFRDI1NTE5In0K.eyJleHAiOjE1ODMyMzM2NjksImlhdCI6MTU4MzIzMzY1NCwibmJmIjoxNTgzMjMzNjU0fQo"))
	assert.Error(t, err, "FORMAT ERROR")
	_, _, _, _, _, err = Parse([]byte("eyJhbGciOiJFRDI1NTE5In0K.eyJleHAiOjE1ODMyMzM2NjksImlhdCI6MTU4MzIzMzY1NCwibmJmIjoxNTgzMjMzNjU0fQo.YvtfzF8U6N-NmNj2imi3GcVK3fjpgEZ2dmbxDLugyDl1WW1bBK1eRCs2vQf73i7RYJrTWVFeaROodxDrc8_qBQ"))
	assert.NilError(t, err)
}
