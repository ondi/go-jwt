//
//
//

package jwt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
)

func Sign(s Signer, bits int64, payload []byte) (res bytes.Buffer, err error) {
	writer := base64.NewEncoder(base64.RawURLEncoding, &res)
	writer.Write([]byte(`{"alg":"` + s.Name() + strconv.FormatInt(bits, 10) + `"}`))
	writer.Close()

	res.WriteByte(byte('.'))

	writer = base64.NewEncoder(base64.RawURLEncoding, &res)
	writer.Write(payload)
	writer.Close()

	var temp []byte
	if temp, err = s.Sign(bits, res.Bytes()); err != nil {
		return
	}

	res.WriteByte(byte('.'))

	writer = base64.NewEncoder(base64.RawURLEncoding, &res)
	writer.Write(temp)
	writer.Close()
	return
}

func Parse(in []byte) (alg string, bits int64, header []byte, payload []byte, signature []byte, err error) {
	ix_header := bytes.IndexByte(in, byte('.'))
	if ix_header < 10 {
		err = fmt.Errorf("FORMAT ERROR")
		return
	}
	header = make([]byte, base64.RawURLEncoding.DecodedLen(ix_header))
	if _, err = base64.RawURLEncoding.Decode(header, in[:ix_header]); err != nil {
		return
	}
	ix_alg := bytes.Index(header, []byte(`"alg"`))
	if ix_alg == -1 {
		err = fmt.Errorf("ALG ERROR")
		return
	}
	ix_alg += 6
	ix_alg1 := bytes.Index(header[ix_alg:], []byte(`"`))
	if ix_alg1 == -1 {
		err = fmt.Errorf("ALG ERROR")
		return
	}
	ix_alg2 := bytes.Index(header[ix_alg+ix_alg1+1:], []byte(`"`))
	if ix_alg2 == -1 {
		err = fmt.Errorf("ALG ERROR")
		return
	}
	alg = string(header[ix_alg+ix_alg1+1 : ix_alg+ix_alg1+ix_alg2+1])
	if len(alg) < 5 {
		err = fmt.Errorf("ALG ERROR")
		return
	}
	if bits, err = strconv.ParseInt(alg[2:], 0, 64); err != nil {
		return
	}
	ix_payload := bytes.IndexByte(in[ix_header+1:], byte('.'))
	if ix_payload == -1 {
		err = fmt.Errorf("FORMAT ERROR")
		return
	}
	payload = make([]byte, base64.RawURLEncoding.DecodedLen(ix_payload))
	if _, err = base64.RawURLEncoding.Decode(payload, in[ix_header+1:ix_header+1+ix_payload]); err != nil {
		return
	}
	signature = make([]byte, base64.RawURLEncoding.DecodedLen(len(in)-ix_header-1-ix_payload-1))
	if _, err = base64.RawURLEncoding.Decode(signature, in[ix_header+1+ix_payload+1:]); err != nil {
		return
	}
	return
}

func Verify(v Verifier, hash_bits int64, signature []byte, in []byte) (ok bool, err error) {
	if ix_sign := bytes.LastIndexByte(in, byte('.')); ix_sign > -1 {
		ok, err = v.Verify(hash_bits, in[:ix_sign], signature)
	}
	return
}
