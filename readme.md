## Usage

Let's create an election where people with the Estonian id numbers `47101010033` and `36603150241` can vote.

    mkdir -p ../myelection
    cp -t ../myelection *.go *.py
    cd ../myelection
    echo 01010033 36603150241 | python2 eligiblevoters.py # downloads id card public keys from sk.ee

    # look below for instructions on how to generate a certificate
    go run reg-server.go ../SECRET.pem # leave it running and let the people register
    
    go run prepare.go ../SECRET.pem 24h "my election"
    # the time limit is approximate, overestimating doesn't hurt
    # the preparation includes bulk RSA signing and will take a while

    go run vote-server.go ../SECRET.pem # and wait for people to vote

    go run count-votes.go
    
    

## Directory structure

Every election lives in its own directory. Do not store anything private in the election directory, it is intended to be published together with the election results.

Its initial contents:

- `voters/%{id}x.cer` - x509 certificats of eligible voters, in DER binary format
- `*.go` `*.py` - the code used to run the election

The registration server fills in

- `voters/%{id}x.pk` - LSAGS public key
- `voters/%{id}x.sig` - Voters's signature on that public key
- `voters/%{id}x.cargo` - Voter's storage, for encrypted LSAGS secret key.
- `voters/%{id}x.reg` - Registration transcript (not used).

The prepare script creates

- `groups/groups` - Lists of groups' members
- `groups/%{gid}.cargos` - Cargos of everyone in this group
- `groups/%{gid}.pks` - Public keys of everyone in this group
- A corresponding `.sig` file for each of these, containing the server signature for it

The voting server creates the following files:

- `votes/%{gid}s/%{y_tilde}x.vote` - The votes

## Certificates

Generate a self-signed x509 certificate with a RSA keypair (the `cert.pem` is compatible with `voteclient`):

    openssl req -x509 -newkey rsa:2048 -keyout ../secretcert.pem -out cert.pem -days 5 -nodes

Get a plain RSA secret key for the election servers:

    openssl rsa -in ../secretcert.pem -out ../SECRET.pem

Get a plain RSA public key for use with `openssl dgst` tool (for manual verification):

    openssl x509 -pubkey -noout -in cert.pem PUBLIC.pem


## File formats

### The common header

All files signed by the server have the following header:

                        1               2                (64-bit words)
        0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7  (8-bit bytes)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     0 | FILE TYPE TAG |  START TIME   |   END TIME    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     3 |        ELECTION NAME          |   GROUP ID*   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-?-?-?-?-?-?-?-?

The group id field is not present in the common `groups` file.

### Specific formats

All integers are little endian and 8 bytes long unless otherwise noted (some are 2 bytes long).

client->server | Registration request (No header at all)
----------------|-----
`REGISTER`        |file type tag
`uint64`        |voter id
`byte`          |signature algorithm id (0x03 = RSASHA1 for now)
`uint16`        |`sig_size`
`[sig_size]byte`|ID card signature on the LSAGS public key
`[29]byte`      | LSAGS public key
`[]byte`        | Everything else is opque cargo

 `groups`, `GROUPSLL` | Groups' members lists (No group number in header)
----------------|-----
`uint64`        |`n` - number of members in group 0
`[n]uint64`     |members' voter id numbers
...|... (same for next group)


`%{gid}.pks`, `GROUPPKS` | Public keys of members of group with id `gid` |
-------------|-----
`[][29]byte` | Public keys, 29 bytes each


`%{gid}.cargos`, `GROUPCGS` | Cargos of members of group with id `gid` |
-------------|-----
`uin64` | voter id of the owner of the cargo
`uin16` | `size` - size of the cargo
`[size]byte` | the cargo
... | ... (same for next voter)


`%{y_tilde}x.cargos`, `VOTEVOTE` | A vote (the header is not transmitted, but is signed) |
-------------|-----
`uin16` | `size` - size of the vote (message)
`[size]byte` | the vote
