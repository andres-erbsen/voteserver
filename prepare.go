package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

const (
	EL_TAG_SIZE = 8 + 8 + 16
	MAX_GROUP_SIZE = 1000
	LSAGS_PK_SIZE = 29
)

var server_sk *rsa.PrivateKey

func sign(filepath string) {
	file, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	h := sha256.New()
	_, err = io.Copy(h, file)
	if err != nil {
		panic(err)
	}
	server_sig, err := rsa.SignPKCS1v15(rand.Reader, server_sk, crypto.SHA256, h.Sum(nil))
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filepath+".sig", server_sig, os.FileMode(0600))
	if err != nil {
		panic(err)
	}
}

func groups_of_no_more_than(voters []uint64, gs_max int) [][]uint64 {
	n := len(voters)
	n_groups := (n + gs_max - 1) / gs_max
	groups := make([][]uint64, n_groups)
	gs := n / n_groups
	used := 0
	groups_used := 0
	for groups_used < n%n_groups {
		groups[groups_used] = voters[used : used+gs+1]
		used += gs + 1
		groups_used++
	}
	for groups_used < n_groups {
		groups[groups_used] = voters[used : used+gs]
		used += gs
		groups_used++
	}
	return groups
}

func main() {
	if len(os.Args) != 4 {
		panic("usage: vote-server.go SECRETKEY_FILE ELECTION_DURATION ELECTION_NAME")
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

	duration, err := time.ParseDuration(os.Args[2])
	if err != nil {
		panic(err)
	}
	now := time.Now()
	end := now.Add(duration)

	election_tag := make([]byte, 32)
	{
		el_tag_buf := new(bytes.Buffer)
		binary.Write(el_tag_buf, binary.LittleEndian, uint64(now.Unix()))
		binary.Write(el_tag_buf, binary.LittleEndian, uint64(end.Unix()))
		n, err := el_tag_buf.WriteString(os.Args[3])
		if err != nil {
			panic(err)
		}
		if n > 16 {
			panic("Election name must be at most 16 bytes long")
		}
		for i := n; i < 16; i++ {
			el_tag_buf.WriteRune('\x00')
		}
		election_tag = el_tag_buf.Bytes()
		if len(election_tag) != 32 {
			panic("Internal error in election tag generation")
		}
	}

	// get list of registered voters
	pkfiles, err := filepath.Glob(filepath.Join("voters", "*.pk"))
	if err != nil {
		panic(err)
	}
	// shuffle and convert to uint64
	voters := make([]uint64, len(pkfiles))
	for i, r := range mathrand.Perm(len(pkfiles)) {
		_, filename := filepath.Split(pkfiles[r])
		_, err := fmt.Sscan(filename[:len(filename)-len(".pk")], &voters[i])
		if err != nil {
			panic(err)
		}
	}

	groups := groups_of_no_more_than(voters, MAX_GROUP_SIZE)

	os.RemoveAll("votes")
	os.RemoveAll("groups")
	if err := os.Mkdir("votes", 0700); err != nil {
		panic(err)
	}
	if err := os.Mkdir("groups", 0700); err != nil {
		panic(err)
	}

	// write the header to the (voter: group) mapping file
	groupsfile_path := filepath.Join("groups", "groups")
	groupsfile, err := os.OpenFile(groupsfile_path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	if _, err := groupsfile.WriteString("GROUPSLL"); err != nil {
		panic(err)
	}
	if _, err := groupsfile.Write(election_tag); err != nil {
		panic(err)
	}

	for group_number, group_members := range groups {
		if err := os.Mkdir(filepath.Join("votes", fmt.Sprint(group_number)), 0700); err != nil {
			panic(err)
		}

		// file for group members' public keys
		pksfile_path := filepath.Join("groups", fmt.Sprint(group_number, ".pks"))
		pksfile, err := os.OpenFile(pksfile_path, os.O_RDWR|os.O_CREATE, 0600)
		if _, err := pksfile.WriteString("GROUPPKS"); err != nil {
			panic(err)
		}
		if _, err := pksfile.Write(election_tag); err != nil {
			panic(err)
		}
		if err := binary.Write(pksfile, binary.LittleEndian, uint64(group_number)); err != nil {
			panic(err)
		}

		// file for group members' cargo
		cargofile_path := filepath.Join("groups", fmt.Sprint(group_number, ".cargos"))
		cargofile, err := os.OpenFile(cargofile_path, os.O_RDWR|os.O_CREATE, 0600)
		if _, err := cargofile.WriteString("GROUPCGS"); err != nil {
			panic(err)
		}
		if _, err := cargofile.Write(election_tag); err != nil {
			panic(err)
		}
		if err := binary.Write(cargofile, binary.LittleEndian, uint64(group_number)); err != nil {
			panic(err)
		}

		// voter_id -> group_number lookup
		if err := binary.Write(groupsfile, binary.LittleEndian, uint64(len(group_members))); err != nil {
			panic(err)
		}
		for _, voter := range group_members {
			if err := binary.Write(groupsfile, binary.LittleEndian, voter); err != nil {
				panic(err)
			}

			voter_path := filepath.Join("voters", fmt.Sprint(voter))

			var voter_pk []byte
			if voter_pk, err = ioutil.ReadFile(voter_path + ".pk"); err != nil {
				panic(err)
			}
			if len(voter_pk) != LSAGS_PK_SIZE {
				panic(voter_path + ".pk has wrong size")
			}
			if _, err := pksfile.Write(voter_pk); err != nil {
				panic(err)
			}

			var voter_cargo []byte
			if voter_cargo, err = ioutil.ReadFile(voter_path + ".cargo"); err != nil {
				panic(err)
			}
			if len(voter_cargo) >= 1<<16 {
				panic(voter_path + ".cargo too big")
			}
			if err := binary.Write(cargofile, binary.LittleEndian, voter); err != nil {
				panic(err)
			}
			if err := binary.Write(cargofile, binary.LittleEndian, uint16(len(voter_cargo))); err != nil {
				panic(err)
			}
			if _, err := cargofile.Write(voter_cargo); err != nil {
				panic(err)
			}
		}

		cargofile.Close()
		sign(cargofile_path)
		pksfile.Close()
		sign(pksfile_path)
	}
	groupsfile.Close()
	sign(groupsfile_path)
}
