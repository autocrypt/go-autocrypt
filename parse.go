package autocrypt

import (
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var (
	ErrUnknownType   = errors.New("unkown type")
	ErrUnknownPrefer = errors.New("unkown prefer")
	ErrUnknownAttr   = errors.New("unkown attribute")
	ErrParse         = errors.New("parse error")
	ErrNoHeader      = errors.New("no AUTOCRYPT header found")
)

const (
	attrTo              = "to"
	attrKey             = "key"
	attrType            = "type"
	attrPreferEncrypted = "prefer-encrypted"

	autocryptHeader = "AUTOCRYPT"
)

func ParseHeader(mailHeader mail.Header) (*Header, error) {
	header := mailHeader.Get(autocryptHeader)

	if len(header) == 0 {
		return nil, ErrNoHeader
	}

	var (
		parsed Header
		part   string
	)

	for len(header) > 0 {
		i := strings.Index(header, ";")
		if i < 0 {
			part = header
			header = ""
		} else {
			part = header[:i]
			header = header[i+1:]
		}

		part = strings.Trim(part, " \t\n\r;")

		i = strings.Index(part, "=")
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
			t, err := parseType(v)
			if err != nil {
				return nil, err
			}

			parsed.Type = t
		case attrPreferEncrypted:
			pe, err := parsePreferEncrypted(v)
			if err != nil {
				return nil, err
			}

			parsed.PreferEncrypted = pe
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

func parseType(opt string) (TypeOption, error) {
	if opt == "" || opt == typeMap[TypeOpenPGP] {
		return TypeOpenPGP, nil
	}

	return TypeInvalid, ErrUnknownType
}

func parsePreferEncrypted(opt string) (bool, error) {
	if opt == preferEncryptedMap[true] {
		return true, nil
	}

	if opt == "" || opt == preferEncryptedMap[false] {
		return false, nil
	}

	return false, ErrUnknownPrefer
}
