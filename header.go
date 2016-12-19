package inbome

import (
	"golang.org/x/crypto/openpgp"
)

const (
	PreferEncryptedStringYes = "yes"
	PreferEncryptedStringNo  = "no"
)

type Attr string

type TypeOption int

const (
	TypeOpenPGP TypeOption = iota
	TypeInvalid

	TypeStringOpenPGP = "p"
)

type Header struct {
	To              string
	Key             *openpgp.Entity
	PreferEncrypted bool
	Type            TypeOption

	Uncritical map[string]string
}
