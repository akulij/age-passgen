package main

import (
	"fmt"
	"time"
	"unsafe"
    "errors"

	"crypto/sha256"
	"golang.org/x/crypto/curve25519"

	"filippo.io/age"
)

type X25519Identity struct {
	secretKey, ourPublicKey []byte
}

func main() {
	var passphrase string

	fmt.Print("Enter password: ")
	fmt.Scanln(&passphrase)

	sum := sha256.Sum256([]byte(passphrase))
	fmt.Printf("Password hash: %x\n", sum)

    k, err := newX25519IdentityFromScalar(sum[:])
	if err != nil {
		fmt.Printf("internal error: %v", err)
	}

	fmt.Printf("Public key: %s\n", k.Recipient())

	fmt.Printf("# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("# public key: %s\n", k.Recipient())
	fmt.Printf("%s\n", k)
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
