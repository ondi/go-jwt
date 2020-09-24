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
	Alg      string `json:"alg"`
	HashBits int64  `json:"-"`
}

func Sign(s Signer, bits int64, payload map[string]interface{}) (res bytes.Buffer, err error) {
	writer := base64.NewEncoder(base64.RawURLEncoding, &res)
	if err = json.NewEncoder(writer).Encode(Header_t{Alg: s.Name() + strconv.FormatInt(bits, 10)}); err != nil {
		return
	}
	writer.Close()
	res.WriteByte(byte('.'))
	writer = base64.NewEncoder(base64.RawURLEncoding, &res)
	if err = json.NewEncoder(writer).Encode(payload); err != nil {
		return
	}
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

func Parse(in []byte) (header Header_t, payload map[string]interface{}, signature []byte, err error) {
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
	if header.HashBits, err = strconv.ParseInt(header.Alg[2:], 0, 64); err != nil {
		return
	}
	ix_sign := bytes.LastIndexByte(in, byte('.'))
	if ix_sign <= ix_header {
		err = fmt.Errorf("FORMAT ERROR")
		return
	}
	signature = make([]byte, base64.RawURLEncoding.DecodedLen(len(in)-ix_sign-1))
	if _, err = base64.RawURLEncoding.Decode(signature, in[ix_sign+1:]); err != nil {
		return
	}
	err = json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, bytes.NewBuffer(in[ix_header+1:ix_sign]))).Decode(&payload)
	return
}

func Verify(v Verifier, hash_bits int64, signature []byte, in []byte) (ok bool, err error) {
	if ix_sign := bytes.LastIndexByte(in, byte('.')); ix_sign > -1 {
		ok, err = v.Verify(hash_bits, in[:ix_sign], signature)
	}
	return
}

func Validate(payload map[string]interface{}, nbf int64, exp int64) (ok bool, err error) {
	var ts float64
	var temp interface{}
	// not before
	if temp, ok = payload["nbf"]; ok {
		if ts, ok = temp.(float64); !ok {
			return false, fmt.Errorf("nbf format error")
		}
		if int64(ts) > nbf {
			return false, fmt.Errorf("nbf")
		}
	}
	// expiration
	if temp, ok = payload["exp"]; ok {
		if ts, ok = temp.(float64); !ok {
			return false, fmt.Errorf("exp format error")
		}
		if int64(ts) < exp {
			return false, fmt.Errorf("exp")
		}
	}
	return true, nil
}
