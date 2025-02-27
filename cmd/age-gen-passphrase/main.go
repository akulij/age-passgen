package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strconv"
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
    age-passgen [-o OUTPUT] [--raw-input]

Options:
    -o, --output OUTPUT       Write the result to the file at path OUTPUT.
    --raw-output              Print stripped keys (without additional text or comments)
    --entropy-level VALUE     Manages required strenght of password (more info down below)

Mostly similar to age-keygen
Required password strenght can be changes via --entropy-level flag. Possible values
high, medium (default), low, verylow, stupid and numbers from 1 to 4 (inclusive).

Each word or number is mapped following this list:
- high    (or 4) - 44 characters
- medium  (or 3) - 22 characters
- low     (or 2) - 12 characters
- verylow (or 1) -  8 characters
- stupid         - no limit
`

func main() {
	log.SetFlags(0)
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s", usage) }

	var (
		rawOutput    bool
		outputFile   string
		entropyLevel string
	)

	flag.BoolVar(&rawOutput, "raw-output", false, "Print stripped keys (without additional text or comments)")
	flag.StringVar(&outputFile, "o", "", "Write the result to the file at path OUTPUT")
	flag.StringVar(&outputFile, "output", "", "Write the result to the file at path OUTPUT")
	flag.StringVar(&entropyLevel, "entropy-level", "medium", "Manages required strenght of password. Read more in --help")
	flag.Parse()

	eLevel, err := parseEntropyLevel(entropyLevel)
	if err != nil {
		errorf("error while parsing --entropy-level argument: %s\n", err)
	}

	passbytes, err := getPasswordBytes()
	if err != nil {
		errorf("Failed to get password, error: %s\n", err)
	}
	valid := isEntropyValid(passbytes, eLevel)
	if !valid {
		errorf("You should choose stroger password!!! (or change entropy level, read more with --help)\n")
	}

	sum := sha256.Sum256(passbytes)

	k, err := newX25519IdentityFromScalar(sum[:])
	if err != nil {
		errorf("internal error: %v", err)
	}

	// if user is not seeing private keyfile, which also contains public key,
	// also duplicate public key it to stderr,
	// but if user sees public key via stdout, no need for duplication
	if outputFile != "" {
		if !rawOutput {
			fmt.Printf("Public key: %s\n", k.Recipient())
		} else {
			fmt.Printf("%s", k.Recipient())
		}
	}

	output := os.Stdout
	if outputFile != "" {
		output, err = os.Create(outputFile)
		if err != nil {
			errorf("failed to create output file, error: %s", err)
		}
	}

	err = writeSecretKey(output, k, !rawOutput)
	if err != nil {
		fmt.Printf("Failed to write secret key to file, error: %s\n", err)
	}
}

func parseEntropyLevel(entropyLevel string) (int, error) {
	if i, err := strconv.Atoi(entropyLevel); err == nil {
		if i == 0 {
			return 0, errors.New("No such entropy level `0`, try `stupid`")
		} else if 1 <= i && i <= 4 {
			return i, nil
		} else {
			return 0, errors.New("Wrong entropy level `" + strconv.Itoa(i) + "`, level should be within range 1 to 4")
		}
	}
	//if it is not number, let's try words
	levelWords := [...]string{"stupid", "verylow", "low", "medium", "high"}
	idx := slices.Index(levelWords[:], entropyLevel)
	if idx == -1 {
		return 0, errors.New("Such entropy level does not exists: " + entropyLevel + "\nMay be misstyped?")
	}

	return idx, nil
}

func isEntropyValid(passbytes []byte, entropyLevel int) bool {
	lengthsMap := [...]int{0, 8, 12, 22, 44}

	return len(passbytes) >= lengthsMap[entropyLevel]
}

func getPasswordBytes() ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "Enter password: ")
		passbytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return passbytes, err
	} else {
		return io.ReadAll(os.Stdin)
	}
}

func writeSecretKey(f *os.File, key *age.X25519Identity, verbose bool) error {
	var err error

	if verbose {
		_, err = fmt.Fprintf(f, "# created: %s\n", time.Now().Format(time.RFC3339))
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(f, "# public key: %s\n", key.Recipient())
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(f, "%s\n", key)
	} else {
		_, err = fmt.Fprintf(f, "%s", key)
	}

	return err
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
	log.Fatalf("age-passgen ERROR: "+format, v...)
}
