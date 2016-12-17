package parse

import (
	"bufio"
	"net/mail"
	"strings"

	"golang.org/x/crypto/openpgp"
)

type TypeOption string
type PreferEncryptOption string

const (
	TypeOpenPGP TypeOption = "OpenPGP"

	PreferEncryptYes PreferEncryptOption = "yes"
	PreferEncryptNo  PreferEncryptOption = "no"
)

type InbomeHeader struct {
	To            string
	Key           *openpgp.Entity
	PreferEncrypt PreferEncryptOption
	Type          TypeOption

	Uncritical map[string]string
}

func (h *InbomeHeader) String() string {

}

const (
	attrTo            = "to"
	attrKey           = "key"
	attrType          = "type"
	attrPreferEncrypt = "prefer-encrypted"
)

func ParseHeader(header string) (*InbomeHeader, error) {
	var parsed InbomeHeader

	r := bufio.NewReader(strings.NewReader(header))

	for {
		part, err := r.ReadString(";")
		if err != nil {
			break
		}

		part = strings.Trim(part, " \t\n\r")

		kv := strings.Split(part, "=")

		switch kv[0] {
		case attrTo:
			parsed.To = kv[1]
		case attrKey:
			key, err = parseKey(kv[1])
			if err != nil {
				return nil, err
			}

			parsed.Key = key
		case attrType:
			t := TypeOption(kv[1])

			if t != TypeOpenPGP {
				return nil, ErrUnknownType
			}

			parsed.Type = t
		case attrPreferEncrypt:
			pe := PreferEncryptOption(kv[1])

			if pe != PreferEncryptYes && pe != PreferEncryptNo {
				return nil, ErrUnknownPreferOption
			}
			parsed.PreferEncrypt = pe
		default:
			if kv[0][0] != "_" {
				return nil, ErrUnknownAttr
			}

			if parsed.Uncritical == nil {
				parsed.Uncritical = make(map[string]string)
			}

			parsed.Uncritical[kv[0]] = kv[1]
		}
	}
}

// TODO
func parseKey(b64Key string) *openpgp.Entity {
	fmt.Println(b64Key)
	return nil
}
