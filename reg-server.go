// Written by Andres Erbsen, distributed under GPLv3
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

const LSAGS_PK_SIZE = 29

var server_sk *rsa.PrivateKey

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("REG"))
}

func regHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	postdata, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	buf := bytes.NewBuffer(postdata)

	var voter_id uint64
	if binary.Read(buf, binary.LittleEndian, &voter_id) != nil {
		return
	}
	var voucher_type uint8
	if binary.Read(buf, binary.LittleEndian, &voucher_type) != nil {
		return
	}
	var sig_len uint16
	if binary.Read(buf, binary.LittleEndian, &sig_len) != nil {
		return
	}

	if int(sig_len+LSAGS_PK_SIZE) > len(postdata) {
		return
	}

	sig := make([]byte, sig_len)
	_, err = io.ReadFull(buf, sig)
	if err != nil {
		return
	}
	pk := make([]byte, LSAGS_PK_SIZE)
	_, err = io.ReadFull(buf, pk)
	if err != nil {
		return
	}
	cargo, err := ioutil.ReadAll(buf)
	if err != nil {
		return
	}

	sig_type := x509.SignatureAlgorithm(voucher_type)
	voter_file := filepath.Join("voters", fmt.Sprintf("%d", voter_id))
	cert_der, err := ioutil.ReadFile(voter_file + ".cer")
	if err != nil {
		return
	}
	cert, err := x509.ParseCertificate(cert_der)
	if err != nil {
		return
	}
	if cert.CheckSignature(sig_type, pk, sig) != nil {
		return
	}

	if ioutil.WriteFile(voter_file+".sig", sig, os.FileMode(0600)) != nil {
		return
	}
	if ioutil.WriteFile(voter_file+".pk", pk, os.FileMode(0600)) != nil {
		return
	}
	if ioutil.WriteFile(voter_file+".cargo", cargo, os.FileMode(0600)) != nil {
		return
	}

	h := sha256.New()
	if _, err := h.Write([]byte("REGISTER")); err != nil {
		return
	}
	if _, err := h.Write(postdata); err != nil {
		return
	}
	server_sig, err := rsa.SignPKCS1v15(rand.Reader, server_sk, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return
	}

	w.Write(server_sig)
	ioutil.WriteFile(voter_file+".reg", postdata, os.FileMode(0600))
	fmt.Println(voter_id, "registered successfully")
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: vote-server.go SECRETKEY_FILE")
	}
	server_sk_raw, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	server_sk_pem, _ := pem.Decode(server_sk_raw)
	if server_sk_pem == nil {
		panic("No PEM block in server secret key file?")
	}
	server_sk, err = x509.ParsePKCS1PrivateKey(server_sk_pem.Bytes)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/register", regHandler)
	panic(http.ListenAndServeTLS(":10443", "cert.pem", os.Args[1], nil))
}
