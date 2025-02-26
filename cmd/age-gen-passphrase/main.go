package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"
	"unsafe"

	"golang.org/x/term"

	"crypto/sha256"
	"golang.org/x/crypto/curve25519"

	"filippo.io/age"
)

type X25519Identity struct {
	secretKey, ourPublicKey []byte
}

const usage = `Usage:
    age-gen-passphrase [-o OUTPUT] [--raw-input]

Options:
    -o, --output OUTPUT       Write the result to the file at path OUTPUT.
    --raw-output              Print stripped keys (without additional text or comments)

Everything is similar to age-keygen`

func main() {
	log.SetFlags(0)
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var (
		rawOutput  bool
		outputFile string
	)

	flag.BoolVar(&rawOutput, "raw-output", false, "Print stripped keys (without additional text or comments)")
	flag.StringVar(&outputFile, "o", "", "Write the result to the file at path OUTPUT")
	flag.StringVar(&outputFile, "output", "", "Write the result to the file at path OUTPUT")
	flag.Parse()

	passbytes, err := getPasswordBytes()
	if err != nil {
		errorf("Failed to get password, error: %s\n", err)
	}

	sum := sha256.Sum256(passbytes)

	k, err := newX25519IdentityFromScalar(sum[:])
	if err != nil {
		errorf("internal error: %v", err)
	}

	// if user is not seeing private keyfile, which also contains public key,
	// also duplicate public key it to stderr,
	// but if user sees public key via stdout, no need for duplication
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintf(os.Stderr, "Public key: %s\n", k.Recipient())
	}

	err = writeSecretKey(os.Stdout, k)
	if err != nil {
		fmt.Printf("Failed to write secret key to file, error: %s\n", err)
	}
}

func getPasswordBytes() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Enter password: ")
		passbytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return passbytes, err
	} else {
		return io.ReadAll(os.Stdin)
	}
}

func writeSecretKey(f *os.File, key *age.X25519Identity) error {
	var err error

	_, err = fmt.Fprintf(f, "# created: %s\n", time.Now().Format(time.RFC3339))
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f, "# public key: %s\n", key.Recipient())
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f, "%s\n", key)
	if err != nil {
		return err
	}

	return nil
}

// almost a copy of private function in age/x25519.go
func newX25519IdentityFromScalar(secretKey []byte) (*age.X25519Identity, error) {
	if len(secretKey) != curve25519.ScalarSize {
		return nil, errors.New("invalid X25519 secret key")
	}
	i := &X25519Identity{
		secretKey: make([]byte, curve25519.ScalarSize),
	}
	copy(i.secretKey, secretKey)
	i.ourPublicKey, _ = curve25519.X25519(i.secretKey, curve25519.Basepoint)
	return (*age.X25519Identity)(unsafe.Pointer(i)), nil
}

func errorf(format string, v ...interface{}) {
	log.Fatalf("age-gen-passphrase ERROR: "+format, v...)
}
