// Command genkey generates a dev Ed25519 keypair for JWT_PRIVATE_KEY.
// Not part of the running service.
package main

import (
	"fmt"
	"os"

	"github.com/haribabuk113/iam/internal/adapters/outbound/jwtsign"
)

func main() {
	priv, pub, err := jwtsign.GenerateKeyPair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "genkey:", err)
		os.Exit(1)
	}
	fmt.Println("# JWT_PRIVATE_KEY (keep secret — load via a secret manager in prod)")
	fmt.Print(string(priv))
	fmt.Println("# public key, for reference only")
	fmt.Print(string(pub))
}
