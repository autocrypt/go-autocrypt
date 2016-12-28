package autocrypt

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/openpgp"
)

type Attr string

type TypeOption int

const (
	TypeOpenPGP TypeOption = iota
	TypeInvalid
)

var (
	typeMap = map[TypeOption]string{
		TypeOpenPGP: "p",
		TypeInvalid: "invalid",
	}

	preferEncryptedMap = map[bool]string{
		true:  "yes",
		false: "no",
	}
)

type Header struct {
	To              string
	Key             *openpgp.Entity
	PreferEncrypted bool
	Type            TypeOption

	Uncritical map[string]string
}

func (h *Header) String() string {
	str := ""

	str += fmt.Sprintf("%s=%s;", attrTo, h.To)
	str += fmt.Sprintf("%s=%s;", attrPreferEncrypted, preferEncryptedMap[h.PreferEncrypted])
	str += fmt.Sprintf("%s=%s;", attrType, typeMap[h.Type])

	for k, v := range h.Uncritical {
		str += fmt.Sprintf("%s=%s;", k, v)
	}

	if h.Key != nil {
		buf := bytes.NewBuffer(nil)
		h.Key.Serialize(
			base64.NewEncoder(base64.StdEncoding, buf))

		str += fmt.Sprintf("%s=%s;", attrKey, wrap(buf.String()))
	}

	return fmt.Sprintf("%s: %s", autocryptHeader, str)
}

const nCols = 76

func wrap(s string) string {
	buf := bytes.NewBuffer(nil)

	for len(s) > 0 {
		c := nCols
		if len(s) < nCols {
			c = len(s)
		}

		fmt.Fprintf(buf, "\n %s", s[:c])
		s = s[c:]
	}

	return buf.String()
}
