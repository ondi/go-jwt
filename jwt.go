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
	"time"
)

type Header_t struct {
	Alg string `json:"alg"`
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

func Verify(v Verifier, in []byte) (payload map[string]interface{}, ok bool, err error) {
	ix_payload := bytes.IndexByte(in, byte('.'))
	if ix_payload == -1 {
		err = fmt.Errorf("FORMAT ERROR")
		return
	}
	ix_sign := bytes.IndexByte(in[ix_payload+1:], byte('.'))
	if ix_sign == -1 {
		err = fmt.Errorf("FORMAT ERROR")
		return
	}
	ix_sign += ix_payload + 1
	var header Header_t
	if err = json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, bytes.NewBuffer(in[:ix_payload]))).Decode(&header); err != nil {
		return
	}
	if len(header.Alg) < 5 {
		err = fmt.Errorf("ALG NOT SUPPORTED")
		return
	}
	var bits int
	if bits, err = strconv.Atoi(header.Alg[2:]); err != nil {
		return
	}
	sign := make([]byte, base64.RawURLEncoding.DecodedLen(len(in)-ix_sign-1))
	if _, err = base64.RawURLEncoding.Decode(sign, in[ix_sign+1:]); err != nil {
		return
	}
	if ok, err = v.Verify(bits, in[:ix_sign], sign); err != nil || !ok {
		return
	}
	err = json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, bytes.NewBuffer(in[ix_payload+1:ix_sign]))).Decode(&payload)
	return
}

func Validate(payload map[string]interface{}) error {
	now := time.Now().Unix()
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
