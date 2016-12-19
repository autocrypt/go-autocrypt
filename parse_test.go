package inbome

import (
	"net/mail"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
	pgperrors "golang.org/x/crypto/openpgp/errors"
)

var (
	// table of errors. rest is nil
	errTable = map[string]error{
		"unknown-type.eml":             ErrUnknownType,
		"rsa2048-unknown-critical.eml": ErrUnknownAttr,
		"no_inbome.eml":                ErrNoHeader,

		// TODO known breakage
		"25519-simple.eml": pgperrors.UnsupportedError("public key type: 22"),
	}

	stateTable = map[string]func(*Header) bool{
		"no_inbome.eml": func(h *Header) bool {
			return h == nil
		},
		"unknown-type.eml": func(h *Header) bool {
			return h == nil
		},
		"rsa4096-simple.eml": func(h *Header) bool {
			return h != nil &&
				h.To == "alice@testsuite.autocrypt.org" &&
				h.Key != nil &&
				checkKey(h.Key) &&
				!h.PreferEncrypted &&
				h.Type == TypeOpenPGP &&
				h.Uncritical == nil
		},
		"rsa2048-explicit-type.eml": func(h *Header) bool {
			return h != nil &&
				h.To == "alice@testsuite.autocrypt.org" &&
				h.Key != nil &&
				checkKey(h.Key) &&
				!h.PreferEncrypted &&
				h.Type == TypeOpenPGP &&
				h.Uncritical == nil
		},
		"rsa2048-unknown-critical.eml": func(h *Header) bool {
			// due to error in parse
			return h == nil
		},
		"rsa2048-simple-to-bot.eml": func(h *Header) bool {
			return h != nil &&
				h.To == "alice@testsuite.autocrypt.org" &&
				h.Key != nil &&
				checkKey(h.Key) &&
				!h.PreferEncrypted &&
				h.Type == TypeOpenPGP &&
				h.Uncritical == nil
		},
		"25519-simple.eml": func(h *Header) bool {
			// TODO known breakage
			return h == nil
		},
		"rsa2048-simple.eml": func(h *Header) bool {
			return h != nil &&
				h.To == "alice@testsuite.autocrypt.org" &&
				h.Key != nil &&
				checkKey(h.Key) &&
				!h.PreferEncrypted &&
				h.Type == TypeOpenPGP &&
				h.Uncritical == nil
		},
		"rsa2048-unknown-non-critical.eml": func(h *Header) bool {
			return h != nil &&
				h.To == "alice@testsuite.autocrypt.org" &&
				h.Key != nil &&
				checkKey(h.Key) &&
				!h.PreferEncrypted &&
				h.Type == TypeOpenPGP &&
				h.Uncritical != nil &&
				h.Uncritical["_monkey"] == "ignore"
		},
	}
)

func TestParse(t *testing.T) {
	dir, err := os.Open("data")
	if err != nil {
		t.Fatal(err)
	}

	emls, err := dir.Readdir(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, emlFI := range emls {
		emlName := emlFI.Name()

		if !strings.HasSuffix(emlName, ".eml") {
			continue
		}

		emlFile, err := os.Open("data/" + emlName)
		if err != nil {
			t.Fatal(err)
		}

		msg, err := mail.ReadMessage(emlFile)
		if err != nil {
			t.Fatal(err)
		}

		hdr, err := ParseHeader(msg.Header)
		if err != errTable[emlName] {
			t.Fatal(emlName, err)
		}

		t.Logf("%s:\n%v\n", emlName, hdr)
	}
}

func checkKey(e *openpgp.Entity) bool {
	return e.PrimaryKey != nil &&
		e.PrivateKey == nil &&
		len(e.Subkeys) == 1 &&
		e.Subkeys[0].PublicKey != nil &&
		e.Subkeys[0].PrivateKey == nil &&
		e.Subkeys[0].Sig != nil
}
