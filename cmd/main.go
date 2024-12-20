package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"github.com/go-piv/piv-go/v2/piv"
	"log"
	"net/http"
	"yubikey_wallet/internal"
	"yubikey_wallet/internal/wallet"
)

type Action string

const (
	GenKeys   Action = "gen-keys"
	SendTrx   Action = "send-trx"
	RunWallet Action = "run-wallet"
)

func main() {
	var action string

	flag.StringVar(&action, "action", "", "Action to process: gen-keys, send-trx")
	flag.Parse()

	switch Action(action) {
	case GenKeys:
		pubKey := GenNewKeys()
		if pubKey == nil {
			log.Fatalf("failed to create keys")
		}
		log.Printf("Successfully created new RSA keys pair. Pub key: %v", pubKey)

		req := wallet.NewPublicKeyRequest{
			PubKey:   *pubKey,
			UserName: "Виталик Бутерин",
		}
		data, _ := json.Marshal(req)

		_, err := http.Post("http://localhost:8080/register_key", "application/json", bytes.NewReader(data))
		if err != nil {
			log.Fatal(err)
		}

	case SendTrx:
		SendTestTrx()
	case RunWallet:
		wt := wallet.NewWallet()
		wt.Run()
	}
}

func GenNewKeys() *rsa.PublicKey {
	yk, err := internal.GetYubiKey()
	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := internal.CreateNewKey(yk)
	if err != nil {
		log.Fatal(err)
	}

	return pubKey
}

func SendTestTrx() {
	yk, err := internal.GetYubiKey()
	if err != nil {
		log.Fatal(err)
	}

	keyInfo, err := yk.KeyInfo(piv.SlotAuthentication)
	if err != nil {
		log.Fatalf("failed to get key info: %v", err)
	}

	pubKey := keyInfo.PublicKey
	pubRSA, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("failed to convert pub key to rsa: %v", err)
	}

	log.Printf("Public key: %v", pubRSA)

	signer := internal.GetSigner(yk, pubRSA)

	data := sha256.Sum256([]byte("your data to sign"))
	out, err := signer.Sign(rand.Reader, data[:], crypto.SHA256)
	if err != nil {
		log.Fatalf("signing failed: %v", err)
	}

	req := wallet.TrxRequest{
		PubKey:     *pubRSA,
		HashedData: data[:],
		Signature:  out,
	}

	rawReq, _ := json.Marshal(req)

	_, err = http.Post("http://localhost:8080/trx", "application/json", bytes.NewReader(rawReq))
	if err != nil {
		log.Fatal(err)
	}

}
