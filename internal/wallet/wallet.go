package wallet

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type Wallet struct {
	balances map[rsa.PublicKey]int64
	srv      *http.Server
}

type NewPublicKeyRequest struct {
	PubKey   rsa.PublicKey
	UserName string
}

type TrxRequest struct {
	PubKey     rsa.PublicKey
	HashedData []byte
	Signature  []byte
}

func parseRequest[T any](r *http.Request) (*T, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var data T
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func NewWallet() *Wallet {
	wt := &Wallet{
		balances: map[rsa.PublicKey]int64{},
	}

	srvMux := http.NewServeMux()
	srvMux.HandleFunc("/register_key", func(w http.ResponseWriter, req *http.Request) {
		wt.handleRegisterKey(w, req)
	})
	srvMux.HandleFunc("/trx", func(w http.ResponseWriter, req *http.Request) {
		wt.handleTrx(w, req)
	})
	wt.srv = &http.Server{Addr: "localhost:8080", Handler: srvMux}

	return wt
}

func (wt *Wallet) Run() {
	err := wt.srv.ListenAndServe()
	fmt.Println(err.Error())
}

func (wt *Wallet) handleRegisterKey(w http.ResponseWriter, req *http.Request) {
	body, err := parseRequest[NewPublicKeyRequest](req)
	if err != nil {
		panic(err.Error())
	}

	_, ok := wt.balances[body.PubKey]
	if !ok {
		wt.balances[body.PubKey] = 0
	}

	log.Println("Success register user")
	w.WriteHeader(http.StatusAccepted)
}

func (wt *Wallet) handleTrx(w http.ResponseWriter, req *http.Request) {
	body, err := parseRequest[TrxRequest](req)
	if err != nil {
		panic(err.Error())
	}

	if err := rsa.VerifyPKCS1v15(&body.PubKey, crypto.SHA256, body.HashedData[:], body.Signature); err != nil {
		log.Println("Failed to verify trx")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	log.Println("Trx verified")
}
