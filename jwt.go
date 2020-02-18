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
	HashBits int    `json:"-"`
}

func Sign(s Signer, bits int, payload map[string]interface{}) (res bytes.Buffer, err error) {
	writer := base64.NewEncoder(base64.RawURLEncoding, &res)
	if err = json.NewEncoder(writer).Encode(Header_t{Alg: s.Name(bits)}); err != nil {
		return
	}
	writer.Close() // flush
	res.WriteByte(byte('.'))
	if err = json.NewEncoder(writer).Encode(payload); err != nil {
		return
	}
	writer.Close() // flush
	var temp []byte
	if temp, err = s.Sign(bits, res.Bytes()); err != nil {
		return
	}
	res.WriteByte(byte('.'))
	writer.Write(temp)
	writer.Close() // flush
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
	if header.HashBits, err = strconv.Atoi(header.Alg[2:]); err != nil {
		return
	}
	ix_sign := bytes.LastIndexByte(in, byte('.'))
	signature = make([]byte, base64.RawURLEncoding.DecodedLen(len(in)-ix_sign-1))
	if _, err = base64.RawURLEncoding.Decode(signature, in[ix_sign+1:]); err != nil {
		return
	}
	err = json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, bytes.NewBuffer(in[ix_header+1:ix_sign]))).Decode(&payload)
	return
}

func Verify(v Verifier, hash_bits int, signature []byte, in []byte) (ok bool, err error) {
	if ix_sign := bytes.LastIndexByte(in, byte('.')); ix_sign > -1 {
		ok, err = v.Verify(hash_bits, in[:ix_sign], signature)
	}
	return
}

func Validate(payload map[string]interface{}, now int64) error {
	// not before
	if temp, ok := payload["nbf"]; ok {
		if nbf, ok := temp.(float64); ok {
			if now < int64(nbf) {
				return fmt.Errorf("nbf")
			}
		} else {
			return fmt.Errorf("nbf format error")
		}
	}
	// expiration
	if temp, ok := payload["exp"]; ok {
		if exp, ok := temp.(float64); ok {
			if now > int64(exp) {
				return fmt.Errorf("exp")
			}
		} else {
			return fmt.Errorf("exp format error")
		}
	}
	return nil
}
