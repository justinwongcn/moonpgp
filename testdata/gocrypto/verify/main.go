// Command verify reads the six go-crypto interop fixtures from a directory
// using go-crypto's own high-level reader, prints the packet sequence it sees
// and decrypts the three messages.
//
// It is the second, implementation-level half of the structure comparison:
// inspect_fixtures.py decodes the raw bytes independently of go-crypto, this
// program shows what the producing library reads back (including the exact
// plaintexts the MoonBit tests assert).
//
// Usage (from the parent directory):
//
//	go run ./verify -dir testdata
//	go run ./verify -dir /tmp/gocrypto-fixtures
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	argon2Passphrase = "go-crypto-argon2"
	v6Passphrase     = "go-crypto-v6"
)

var cipherNames = map[packet.CipherFunction]string{
	0: "Plaintext", 1: "IDEA", 2: "3DES", 3: "CAST5", 4: "Blowfish",
	7: "AES128", 8: "AES192", 9: "AES256", 10: "Twofish",
}

var modeNames = map[packet.AEADMode]string{1: "EAX", 2: "OCB", 3: "GCM"}

func cipherName(c packet.CipherFunction) string {
	if n, ok := cipherNames[c]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", c)
}

func modeName(m packet.AEADMode) string {
	if n, ok := modeNames[m]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", m)
}

func readFile(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, name))
}

// dearmor returns the binary packet stream of an ASCII-armored fixture.
func dearmor(data []byte) ([]byte, error) {
	if !bytes.Contains(data, []byte("-----BEGIN PGP")) {
		return data, nil
	}
	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(block.Body)
}

// dumpPackets prints the packet sequence as go-crypto parses it.
func dumpPackets(label string, data []byte) {
	r := bytes.NewReader(data)
	for {
		p, err := packet.Read(r)
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Printf("%s: packet read error: %v\n", label, err)
			return
		}
		switch pkt := p.(type) {
		case *packet.PrivateKey:
			fmt.Printf("%s: secret-key   version=%d algo=%d subkey=%v protected=%v\n",
				label, pkt.Version, pkt.PubKeyAlgo, pkt.IsSubkey, pkt.Encrypted)
		case *packet.PublicKey:
			fmt.Printf("%s: public-key   version=%d algo=%d subkey=%v\n",
				label, pkt.Version, pkt.PubKeyAlgo, pkt.IsSubkey)
		case *packet.SymmetricKeyEncrypted:
			fmt.Printf("%s: SKESK        version=%d cipher=%s aead=%s\n",
				label, pkt.Version, cipherName(pkt.CipherFunc), modeName(pkt.Mode))
		case *packet.EncryptedKey:
			fmt.Printf("%s: PKESK        version=%d key_version=%d algo=%d\n",
				label, pkt.Version, pkt.KeyVersion, pkt.Algo)
		case *packet.SymmetricallyEncrypted:
			if pkt.Version == 2 {
				fmt.Printf("%s: SEIPD        version=2 cipher=%s aead=%s chunk_size_octet=%d\n",
					label, cipherName(pkt.Cipher), modeName(pkt.Mode), pkt.ChunkSizeByte)
			} else {
				fmt.Printf("%s: SEIPD        version=1 protected=%v\n",
					label, pkt.IntegrityProtected)
			}
			// Contents already points at the encrypted payload; there are no
			// further cleartext packets to read.
			return
		case *packet.Signature:
			fmt.Printf("%s: signature    version=%d type=0x%02x algo=%d notations=%d\n",
				label, pkt.Version, uint8(pkt.SigType), pkt.PubKeyAlgo, len(pkt.Notations))
		case *packet.UserId:
			fmt.Printf("%s: user-id      %q\n", label, pkt.Id)
		default:
			fmt.Printf("%s: %T\n", label, p)
		}
	}
}

// verifyKey parses a key fixture, reports its shape and tries to unlock it.
func verifyKey(dir, name, passphrase string) error {
	data, err := readFile(dir, name)
	if err != nil {
		return err
	}
	fmt.Printf("=== %s\n", name)
	raw, err := dearmor(data)
	if err != nil {
		return fmt.Errorf("dearmor: %w", err)
	}
	dumpPackets(name, raw)
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("ReadArmoredKeyRing: %w", err)
	}
	if len(el) != 1 {
		return fmt.Errorf("expected 1 entity, got %d", len(el))
	}
	e := el[0]
	encrypted := e.PrivateKey.Encrypted
	for _, sk := range e.Subkeys {
		encrypted = encrypted || sk.PrivateKey.Encrypted
	}
	if encrypted {
		if err := e.DecryptPrivateKeys([]byte(passphrase)); err != nil {
			return fmt.Errorf("unlock with %q: %w", passphrase, err)
		}
		fmt.Printf("%s: unlocked with %q, still_protected=%v subkeys=%d\n",
			name, passphrase, e.PrivateKey.Encrypted, len(e.Subkeys))
	} else {
		fmt.Printf("%s: not protected, no passphrase needed, subkeys=%d\n", name, len(e.Subkeys))
	}
	fmt.Println()
	return nil
}

func readAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

// verifyMessage decrypts a message fixture and prints the exact plaintext.
func verifyMessage(dir, name, passphrase string, keyring openpgp.EntityList) error {
	data, err := readFile(dir, name)
	if err != nil {
		return err
	}
	fmt.Printf("=== %s\n", name)
	raw, err := dearmor(data)
	if err != nil {
		return fmt.Errorf("dearmor: %w", err)
	}
	dumpPackets(name, raw)
	var prompt openpgp.PromptFunction
	if passphrase != "" {
		prompt = func(_ []openpgp.Key, symmetric bool) ([]byte, error) {
			return []byte(passphrase), nil
		}
	}
	md, err := openpgp.ReadMessage(bytes.NewReader(raw), keyring, prompt, nil)
	if err != nil {
		return fmt.Errorf("ReadMessage: %w", err)
	}
	plaintext, err := readAll(md.UnverifiedBody)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	fmt.Printf("%s: plaintext=%q bytes=%d\n\n", name, plaintext, len(plaintext))
	return nil
}

func main() {
	dir := flag.String("dir", ".", "directory holding the six interop_gocrypto_*.asc fixtures")
	flag.Parse()

	keyFiles := []struct{ name, pass string }{
		{"interop_gocrypto_v4_argon2_key.asc", argon2Passphrase},
		{"interop_gocrypto_v6_argon2_key.asc", argon2Passphrase},
		{"interop_gocrypto_v6_aead_key.asc", ""},
	}
	for _, k := range keyFiles {
		if err := verifyKey(*dir, k.name, k.pass); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", k.name, err)
			os.Exit(1)
		}
	}

	// The v6 AEAD message is encrypted to the unprotected v6 key above.
	keyData, err := readFile(*dir, "interop_gocrypto_v6_aead_key.asc")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read v6 key:", err)
		os.Exit(1)
	}

	msgs := []struct {
		name    string
		pass    string
		keyring openpgp.EntityList
	}{
		{"interop_gocrypto_argon2_msg.asc", argon2Passphrase, nil},
		{"interop_gocrypto_v6_aead_msg.asc", "", keyring},
		{"interop_gocrypto_v6_aead_skesk_msg.asc", v6Passphrase, nil},
	}
	for _, m := range msgs {
		if err := verifyMessage(*dir, m.name, m.pass, m.keyring); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", m.name, err)
			os.Exit(1)
		}
	}
}
