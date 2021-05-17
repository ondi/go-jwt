//
//
//

package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

type Header_t struct {
	Alg  string `json:"alg"`
	Bits int64  `json:"-"`
}

func Sign(s Signer, bits int64, payload []byte) (res bytes.Buffer, err error) {
	writer := base64.NewEncoder(base64.RawURLEncoding, &res)
	json.NewEncoder(writer).Encode(Header_t{Alg: s.Name() + strconv.FormatInt(bits, 10)})
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

func Parse(in []byte) (header Header_t, payload []byte, signature []byte, err error) {
	ix_header := bytes.IndexByte(in, byte('.'))
	if ix_header == -1 {
		err = fmt.Errorf("FORMAT ERROR")
		return
	}
	if err = json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, bytes.NewBuffer(in[:ix_header]))).Decode(&header); err != nil {
		return
	}
	if len(header.Alg) < 5 {
		err = fmt.Errorf("ALG NOT SUPPORTED")
		return
	}
	if header.Bits, err = strconv.ParseInt(header.Alg[2:], 0, 64); err != nil {
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

func Validate(in []byte, nbf int64, exp int64) (res map[string]interface{}, err error) {
	var ts float64
	res = map[string]interface{}{}
	if err = json.Unmarshal(in, &res); err != nil {
		return
	}
	// not before
	if temp, ok := res["nbf"]; ok {
		if ts, ok = temp.(float64); !ok {
			err = fmt.Errorf("nbf format error")
			return
		}
		if int64(ts) > nbf {
			err = fmt.Errorf("nbf")
			return
		}
	}
	// expiration
	if temp, ok := res["exp"]; ok {
		if ts, ok = temp.(float64); !ok {
			err = fmt.Errorf("exp format error")
			return
		}
		if int64(ts) < exp {
			err = fmt.Errorf("exp")
			return
		}
	}
	return
}
