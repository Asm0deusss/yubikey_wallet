package internal

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"github.com/go-piv/piv-go/v2/piv"
	"log"
	"strings"
)

func GetYubiKey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return nil, err
			}
			break
		}
	}

	if yk == nil {
		return nil, err
	}

	return yk, nil
}

func GetSigner(yk *piv.YubiKey, pubRSA *rsa.PublicKey) crypto.Signer {
	priv, err := yk.PrivateKey(piv.SlotAuthentication, pubRSA, piv.KeyAuth{
		PIN: piv.DefaultPIN,
	})
	if err != nil {
		log.Fatalf("getting private key: %v", err)
	}

	s, ok := priv.(crypto.Signer)
	if !ok {
		log.Fatalf("private key didn't implement crypto.Signer")
	}

	return s
}

func CreateNewKey(yk *piv.YubiKey) (*rsa.PublicKey, error) {
	// Generate a private key on the YubiKey.
	key := piv.Key{
		Algorithm:   piv.AlgorithmRSA2048,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	pub, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotAuthentication, key)
	if err != nil {
		return nil, err
	}

	pubRSA, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to cast to rsa.PublicKey")
	}

	return pubRSA, nil
}
