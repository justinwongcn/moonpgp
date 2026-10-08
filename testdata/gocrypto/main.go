// Command gocrypto-fixtures regenerates the six go-crypto interop fixtures
// consumed by src/interop/argon2_cross_test.mbt and
// src/interop/v6_aead_pref_test.mbt.
//
// It is deliberately standalone: a separate Go module pinned to one exact
// github.com/ProtonMail/go-crypto release, so the committed bytes in
// testdata/*.asc can be reproduced without the MoonBit toolchain.
//
// Run it from this directory:
//
//	go run .                     # writes into a fresh temporary directory
//	go run . -out /tmp/fixtures  # writes into a caller-given directory
//	go run . -out /tmp/fixtures -force   # overwrite existing files
//
// Existing files are never overwritten without -force, so the committed
// testdata/*.asc fixtures cannot be clobbered by accident.
//
// Key material, signature salts and AEAD nonces are random: regenerating
// produces structurally equivalent but not byte-identical files. Pass -time
// to pin the key creation timestamp.
package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

const (
	// argon2Passphrase locks the two Argon2 key fixtures and encrypts the
	// Argon2 symmetric message.
	argon2Passphrase = "go-crypto-argon2"
	// v6Passphrase locks/encrypts the v6 AEAD symmetric message. It is
	// deliberately different from argon2Passphrase.
	v6Passphrase = "go-crypto-v6"

	argon2MsgPlaintext = "written by go-crypto with Argon2 S2K\n"
	v6MsgPlaintext     = "written by go-crypto v6 PKESK + SEIPD v2\n"
	v6SkeskPlaintext   = "written by go-crypto v6 SKESK\n"
)

// fixtureNames lists every file this generator writes, in output order.
var fixtureNames = []string{
	"interop_gocrypto_v4_argon2_key.asc",
	"interop_gocrypto_v6_argon2_key.asc",
	"interop_gocrypto_v6_aead_key.asc",
	"interop_gocrypto_argon2_msg.asc",
	"interop_gocrypto_v6_aead_msg.asc",
	"interop_gocrypto_v6_aead_skesk_msg.asc",
}

var errForce = errors.New("pass -force to overwrite")

// argon2S2K is the cheapest legal Argon2id parameter set: t=1, p=1,
// m = 2^5 KiB = 32 KiB. It keeps the cross-implementation tests in the
// default (fast) test suite.
func argon2S2K() *s2k.Config {
	return &s2k.Config{
		S2KMode: s2k.Argon2S2K,
		Argon2Config: &s2k.Argon2Config{
			NumberOfPasses:      1,
			DegreeOfParallelism: 1,
			Memory:              32,
		},
	}
}

// keyCreationConfig is the packet.Config used while the entity is built, i.e.
// while its self-signatures are written. It deliberately does NOT set
// AEADConfig: the committed Argon2 key fixtures advertise SEIPDv1 only
// (Features = 0x01) and carry no Preferred AEAD Ciphersuites subpacket.
func keyCreationConfig(v6 bool, now func() time.Time) *packet.Config {
	return &packet.Config{
		V6Keys:    v6,
		Time:      now,
		S2KConfig: argon2S2K(),
	}
}

// keyProtectionConfig is the packet.Config passed to EncryptPrivateKeys. The
// non-nil AEADConfig is what selects S2K usage octet 253 (AEAD-protected
// secret key material) with OCB mode; the default cipher is AES-128.
func keyProtectionConfig(now func() time.Time) *packet.Config {
	return &packet.Config{
		Time:       now,
		S2KConfig:  argon2S2K(),
		AEADConfig: &packet.AEADConfig{}, // Mode defaults to OCB
	}
}

func armorEncode(blockType string, body []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, blockType, nil)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(body); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// serializeArmoredPrivateKey writes an armored "PGP PRIVATE KEY BLOCK".
func serializeArmoredPrivateKey(e *openpgp.Entity, cfg *packet.Config) ([]byte, error) {
	var raw bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&raw, cfg); err != nil {
		return nil, err
	}
	return armorEncode(openpgp.PrivateKeyType, raw.Bytes())
}

func writeFixture(outDir string, force bool, name string, data []byte) error {
	path := filepath.Join(outDir, name)
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists (pass -force to overwrite)", path)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	fmt.Printf("%-42s %6d bytes  sha256=%x\n", name, len(data), sum)
	return nil
}

func main() {
	outDir := flag.String("out", "", "output directory (default: a fresh temporary directory)")
	force := flag.Bool("force", false, "overwrite files that already exist")
	timeStr := flag.String("time", "", "RFC 3339 key creation time (default: now)")
	flag.Parse()

	var now func() time.Time = time.Now
	if *timeStr != "" {
		t, err := time.Parse(time.RFC3339, *timeStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid -time:", err)
			os.Exit(2)
		}
		now = func() time.Time { return t }
	}

	dir := *outDir
	if dir == "" {
		tmp, err := os.MkdirTemp("", "gocrypto-fixtures-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "temp dir:", err)
			os.Exit(1)
		}
		dir = tmp
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "abs:", err)
		os.Exit(1)
	}

	// Refuse before writing anything, so a run into testdata/ that hits one
	// stale file cannot leave a half-regenerated fixture set behind.
	if !*force {
		for _, name := range fixtureNames {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				fatal("refusing to overwrite "+path, errForce)
			}
		}
	}
	fmt.Printf("go-crypto v1.5.2 fixtures -> %s\n\n", dir)

	// ---------------------------------------------------------------- keys --
	// v4 RSA-2048 primary + v4 RSA-2048 subkey, Argon2id + AES-128/OCB
	// (S2K usage 253), passphrase "go-crypto-argon2".
	v4Key, err := openpgp.NewEntity(
		"GoCrypto v4 Argon2", "argon2 fixture", "fixture@example.com",
		keyCreationConfig(false, now),
	)
	if err != nil {
		fatal("v4 argon2 NewEntity", err)
	}
	if err := v4Key.EncryptPrivateKeys([]byte(argon2Passphrase), keyProtectionConfig(now)); err != nil {
		fatal("v4 argon2 EncryptPrivateKeys", err)
	}
	v4KeyBytes, err := serializeArmoredPrivateKey(v4Key, keyCreationConfig(false, now))
	if err != nil {
		fatal("v4 argon2 serialize", err)
	}
	if err := writeFixture(dir, *force, "interop_gocrypto_v4_argon2_key.asc", v4KeyBytes); err != nil {
		fatal("write", err)
	}

	// v6 RSA-2048 primary + v6 RSA-2048 subkey: V6Keys alone does not change
	// the default public-key algorithm (RSA), it only bumps key/signature
	// versions. Same protection and passphrase as the v4 fixture.
	v6Key, err := openpgp.NewEntity(
		"GoCrypto v6 Argon2", "argon2 fixture", "fixture@example.com",
		keyCreationConfig(true, now),
	)
	if err != nil {
		fatal("v6 argon2 NewEntity", err)
	}
	if err := v6Key.EncryptPrivateKeys([]byte(argon2Passphrase), keyProtectionConfig(now)); err != nil {
		fatal("v6 argon2 EncryptPrivateKeys", err)
	}
	v6KeyBytes, err := serializeArmoredPrivateKey(v6Key, keyCreationConfig(true, now))
	if err != nil {
		fatal("v6 argon2 serialize", err)
	}
	if err := writeFixture(dir, *force, "interop_gocrypto_v6_argon2_key.asc", v6KeyBytes); err != nil {
		fatal("write", err)
	}

	// v6 Ed25519 primary + v6 X25519 subkey, NOT protected (S2K usage 0),
	// advertising Preferred AEAD Ciphersuites = [(AES-128, OCB)]. The
	// AEADConfig is needed both for that preference and for the message below.
	v6AeadCfg := &packet.Config{
		V6Keys:     true,
		Algorithm:  packet.PubKeyAlgoEd25519,
		Time:       now,
		AEADConfig: &packet.AEADConfig{},
	}
	v6AeadKey, err := openpgp.NewEntity(
		"GoCrypto V6", "v6 fixture", "v6@example.com", v6AeadCfg,
	)
	if err != nil {
		fatal("v6 aead NewEntity", err)
	}
	// No EncryptPrivateKeys call: the committed fixture has s2k_usage = 0.
	v6AeadKeyBytes, err := serializeArmoredPrivateKey(v6AeadKey, v6AeadCfg)
	if err != nil {
		fatal("v6 aead serialize", err)
	}
	if err := writeFixture(dir, *force, "interop_gocrypto_v6_aead_key.asc", v6AeadKeyBytes); err != nil {
		fatal("write", err)
	}

	// ------------------------------------------------------------ messages --
	// v4 SKESK + v1 SEIPD with Argon2id t=1/p=1/m=2^5. No AEADConfig here:
	// that is what keeps the message in the v4/v1 shape.
	argon2Msg, err := symmetricallyEncrypt(
		&packet.Config{Time: now, S2KConfig: argon2S2K()},
		argon2Passphrase, argon2MsgPlaintext,
	)
	if err != nil {
		fatal("argon2 message", err)
	}
	if err := writeFixture(dir, *force, "interop_gocrypto_argon2_msg.asc", argon2Msg); err != nil {
		fatal("write", err)
	}

	// v6 PKESK + v2 SEIPD (AES-128/OCB, chunk size byte 12) to the v6 key.
	v6Msg, err := publicKeyEncrypt(v6AeadKey, v6AeadCfg, v6MsgPlaintext)
	if err != nil {
		fatal("v6 message", err)
	}
	if err := writeFixture(dir, *force, "interop_gocrypto_v6_aead_msg.asc", v6Msg); err != nil {
		fatal("write", err)
	}

	// v6 SKESK + v2 SEIPD (AES-128/OCB). The S2K here is iterated-salted
	// (type 3, the go-crypto default), NOT Argon2.
	v6SkeskCfg := &packet.Config{
		Time:       now,
		AEADConfig: &packet.AEADConfig{},
		S2KConfig:  &s2k.Config{S2KMode: s2k.IteratedSaltedS2K},
	}
	v6Skesk, err := symmetricallyEncrypt(v6SkeskCfg, v6Passphrase, v6SkeskPlaintext)
	if err != nil {
		fatal("v6 skesk message", err)
	}
	if err := writeFixture(dir, *force, "interop_gocrypto_v6_aead_skesk_msg.asc", v6Skesk); err != nil {
		fatal("write", err)
	}

	fmt.Println("\ndone; plaintexts and passphrases are listed in README.md")
}

func symmetricallyEncrypt(cfg *packet.Config, passphrase, plaintext string) ([]byte, error) {
	var raw bytes.Buffer
	w, err := armor.Encode(&raw, openpgp.MessageType, nil)
	if err != nil {
		return nil, err
	}
	pt, err := openpgp.SymmetricallyEncrypt(w, []byte(passphrase), nil, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := pt.Write([]byte(plaintext)); err != nil {
		return nil, err
	}
	if err := pt.Close(); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return raw.Bytes(), nil
}

func publicKeyEncrypt(to *openpgp.Entity, cfg *packet.Config, plaintext string) ([]byte, error) {
	var raw bytes.Buffer
	w, err := armor.Encode(&raw, openpgp.MessageType, nil)
	if err != nil {
		return nil, err
	}
	pt, err := openpgp.Encrypt(w, []*openpgp.Entity{to}, nil, nil, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := pt.Write([]byte(plaintext)); err != nil {
		return nil, err
	}
	if err := pt.Close(); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return raw.Bytes(), nil
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "fatal: %s: %v\n", what, err)
	os.Exit(1)
}
