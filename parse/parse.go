package parse

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type TypeOption string
type PreferEncryptOption string

var (
	ErrUnknownType   = errors.New("unkown type")
	ErrUnknownPrefer = errors.New("unkown prefer")
	ErrUnknownAttr   = errors.New("unkown attribute")
	ErrParse         = errors.New("parse error")
)

const (
	TypeOpenPGP TypeOption = "p"

	PreferEncryptYes PreferEncryptOption = "yes"
	PreferEncryptNo  PreferEncryptOption = "no"
)

type Header struct {
	To            string
	Key           *openpgp.Entity
	PreferEncrypt PreferEncryptOption
	Type          TypeOption

	Uncritical map[string]string
}

/*
func (h *Header) String() string {
	return ""
}
*/

const (
	attrTo            = "to"
	attrKey           = "key"
	attrType          = "type"
	attrPreferEncrypt = "prefer-encrypted"
)

func ParseHeader(header string) (*Header, error) {
	var parsed Header

	r := bufio.NewReader(strings.NewReader(header))

	for {
		part, err := r.ReadString(';')
		if err != nil && err != io.EOF {
			break
		}

		if len(part) == 0 {
			break
		}

		part = strings.TrimRight(part, ";")
		part = strings.Trim(part, " \t\n\r")

		i := strings.Index(part, "=")
		if i < 0 {
			return nil, ErrParse
		}

		k := part[:i]
		v := part[i+1:]

		switch k {
		case attrTo:
			parsed.To = v
		case attrKey:
			//key, err := parseKey(v)
			key, err := parseKey(strings.Replace(v, " ", "", -1))
			if err != nil {
				return nil, err
			}

			parsed.Key = key
		case attrType:
			t := TypeOption(v)

			if t != TypeOpenPGP {
				return nil, ErrUnknownType
			}

			parsed.Type = t
		case attrPreferEncrypt:
			pe := PreferEncryptOption(v)

			if pe != PreferEncryptYes && pe != PreferEncryptNo {
				return nil, ErrUnknownPrefer
			}
			parsed.PreferEncrypt = pe
		default:
			if k[0] != '_' {
				return nil, ErrUnknownAttr
			}

			if parsed.Uncritical == nil {
				parsed.Uncritical = make(map[string]string)
			}

			parsed.Uncritical[k] = v
		}
	}

	return &parsed, nil
}

func parseKey(b64Key string) (*openpgp.Entity, error) {
	r := packet.NewReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64Key)))
	return openpgp.ReadEntity(r)
}
