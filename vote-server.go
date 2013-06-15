package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"encoding/hex"
	"fmt"
)

const LSAGS_PK_SIZE = 29
const MAX_GROUP_SIZE = 1000

var server_sk *rsa.PrivateKey
var election_tag []byte

func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("VOTE"))
}

func groupVoteHandler(group string) func(http.ResponseWriter, *http.Request) {
	var group_number uint64
	if _, err := fmt.Sscan(group, &group_number); err != nil {
		panic(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256 + (MAX_GROUP_SIZE+2)*(LSAGS_PK_SIZE))
		postdata, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return
		}
		if len(postdata) < 2+LSAGS_PK_SIZE {
			return
		}

		vote_size := postdata[0] | postdata[1]<<8
		filename := hex.EncodeToString(postdata[2+vote_size:2+vote_size+LSAGS_PK_SIZE]) + ".vote"
		vote_path := filepath.Join("votes", group, filename)

		if Exists(vote_path) {
			return
		} // no re-voting for now

		h := sha256.New()
		if _, err := h.Write([]byte("VOTEVOTE")); err != nil {
			return
		}
		if _, err := h.Write(election_tag); err != nil {
			return
		}
		if err := binary.Write(h, binary.LittleEndian, group_number); err != nil {
			return
		}
		if _, err := h.Write(postdata); err != nil {
			return
		}
		h_val := h.Sum(nil)
		server_sig, err := rsa.SignPKCS1v15(rand.Reader, server_sk, crypto.SHA256, h_val)
		if err != nil {
			return
		}

		if err := ioutil.WriteFile(vote_path, postdata, os.FileMode(0600)); err != nil {
			panic(err)
		}
		w.Write(server_sig)
		fmt.Println("Received a vote ", vote_path)
	}
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: vote-server.go SECRETKEY_FILE")
	}

	election_tag = make([]byte, 32)
	{
		filetype := make([]byte, 8)
		f, err := os.Open(filepath.Join("groups", "groups"))
		defer f.Close()
		if err != nil {
			panic(err)
		}
		if _, err := io.ReadFull(f, filetype); err != nil {
			panic(err)
		}
		if _, err := io.ReadFull(f, election_tag); err != nil {
			panic(err)
		}
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

	groups, err := filepath.Glob(filepath.Join("votes", "*"))
	if err != nil {
		panic(err)
	}
	for _, group := range groups {
		http.HandleFunc("/"+filepath.ToSlash(group),
			groupVoteHandler(filepath.Base(group)))
	}
	http.Handle("/groups/", http.StripPrefix("/groups", http.FileServer(http.Dir("groups/"))))
	http.HandleFunc("/status", statusHandler)
	panic(http.ListenAndServeTLS(":10443", "cert.pem", os.Args[1], nil))
}
