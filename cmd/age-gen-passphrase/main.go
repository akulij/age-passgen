package main

import (
	"errors"
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

func main() {
	passbytes, err := getPasswordBytes()
	if err != nil {
		errorf("Failed to get password, error: %s\n", err)
	}

	sum := sha256.Sum256(passbytes)
	fmt.Printf("Password hash: %x\n", sum)

	k, err := newX25519IdentityFromScalar(sum[:])
	if err != nil {
		errorf("internal error: %v", err)
	}

	fmt.Printf("Public key: %s\n", k.Recipient())

	fmt.Printf("# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("# public key: %s\n", k.Recipient())
	fmt.Printf("%s\n", k)
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
