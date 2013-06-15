package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/andres-erbsen/lsags"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"crypto/x509"
)

const LSAGS_PK_SIZE = 29

func main() {
	valid_pks := make(map[[LSAGS_PK_SIZE]byte]bool)

	election_tag := make([]byte, 32)
	{
		skip := make([]byte, 8)
		f, err := os.Open(filepath.Join("groups", "groups"))
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if _, err := io.ReadFull(f, skip); err != nil {
			panic(err)
		}
		if _, err := io.ReadFull(f, election_tag); err != nil {
			panic(err)
		}
	}
	vouch_sig_files, err := filepath.Glob(filepath.Join("voters", "*.sig"))
	if err != nil {
		panic(err)
	}
	for _, sig_file := range vouch_sig_files {
		sig, err := ioutil.ReadFile(sig_file)
		if err != nil {
			fmt.Println(sig_file, err)
			continue
		}
		pk, err := ioutil.ReadFile(sig_file[:len(sig_file)-len(".sig")] + ".pk")
		if err != nil {
			fmt.Println(sig_file, err)
			continue
		}
		if len(pk) != LSAGS_PK_SIZE {
			fmt.Println(sig_file, "pk is not of the right length")
			continue
		}
		cert_der, err := ioutil.ReadFile(sig_file[:len(sig_file)-len(".sig")] + ".cer")
		if err != nil {
			fmt.Println(sig_file, err)
			continue
		}
		cert, err := x509.ParseCertificate(cert_der)
		if err != nil {
			fmt.Println(sig_file, err)
			continue
		}
		err = cert.CheckSignature(x509.SHA1WithRSA, pk, sig)
		if err == nil {
			var pk_ [LSAGS_PK_SIZE]byte
			copy(pk_[:], pk[:LSAGS_PK_SIZE]) 
			valid_pks[pk_] = true
		} else {
			fmt.Println(sig_file, err)
			continue
		}
	}
	// fmt.Println(valid_pks)

	results := make(map[string]int)
	bad_votes := make(map[string]int)

	groupsvotes, err := filepath.Glob(filepath.Join("votes", "*"))
	if err != nil {
		panic(err)
	}
	for _, groupvotes := range groupsvotes {
		group := filepath.Base(groupvotes)
		group_results := make(map[string]int)
		fmt.Println("Verifying group", group)
		pks, err := ioutil.ReadFile(filepath.Join("groups", group+".pks"))
		if err != nil {
			panic(err)
		}
		if bytes.Compare(pks[8:8+32], election_tag) != 0 {
			panic("Election tag for group " + group + " does not match.")
		}
		pks = pks[8+32+8:] // skip {file, election, group} tags
		if len(pks) % LSAGS_PK_SIZE != 0 {
			panic("Public keys file for group "+group+" is of wring size")
		}
		n := len(pks) / LSAGS_PK_SIZE
		for i := 0; i<n; i++ {
			var pk_ [LSAGS_PK_SIZE]byte
			copy(pk_[:], pks[i*LSAGS_PK_SIZE:(i+1)*LSAGS_PK_SIZE]) 
			if (valid_pks[pk_]) {
				delete(valid_pks, pk_)
			} else {
				fmt.Println(i, pk_)
				panic("Public key "+fmt.Sprint(i)+" in group "+group+" is unbacked!")
			}
		}

		// count cast votes by members of this group
		votefiles, err := filepath.Glob(filepath.Join(groupvotes, "*"))
		if err != nil {
			panic(err)
		}
		for _, votefile := range votefiles {
			vote, err := os.Open(votefile)
			if err != nil {
				panic(err)
			}
			defer vote.Close()
			var msg_size uint16
			if err := binary.Read(vote, binary.LittleEndian, &msg_size); err != nil {
				panic(err)
			}
			msg := make([]byte, int(msg_size))
			if _, err := io.ReadFull(vote, msg); err != nil {
				panic(err)
			}
			sig, err := ioutil.ReadAll(vote)
			if err != nil {
				panic(err)
			}
			err = lsags.Verify(pks, msg, election_tag, sig)
			if err == nil {
				results[string(msg)]++
				group_results[string(msg)]++
			} else {
				bad_votes[group]++
			}
		}
		fmt.Println("Group", group, "results:", group_results, "excluding", bad_votes[group], "invalid votes")
	}
	fmt.Println("Overall results:", results)
}
