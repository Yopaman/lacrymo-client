package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"net"
	"os"

	"github.com/markdingo/netstring"
)

var sKaes []byte
var sKiv []byte
var sKmac []byte
var cKaes []byte
var cKiv []byte
var cKmac []byte

var sMac hash.Hash
var cMac hash.Hash

var sStream cipher.Stream
var cStream cipher.Stream

func main() {

	conn, err := net.Dial("tcp", "lacrymo.tme-crypto.fr:6025")
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	enc := netstring.NewEncoder(conn)
	dec := netstring.NewDecoder(conn)

	diffieHellman(enc, dec, "../private-key.pem", "../server-public-key.pem")

	cBlock, err := aes.NewCipher(cKaes[:16])
	if err != nil {
		panic("crypto error : " + err.Error())
	}
	cStream = cipher.NewCTR(cBlock, cKiv[:16])
	cMac = hmac.New(sha256.New, cKmac[:16])
	sBlock, err := aes.NewCipher(sKaes[:16])
	if err != nil {
		panic("crypto error" + err.Error())
	}
	sStream = cipher.NewCTR(sBlock, sKiv[:16])
	sMac = hmac.New(sha256.New, sKmac[:16])

	go handleTelnet(dec, enc)

	// Send user input to server
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text() + "\r\n" // telnet expects CRLF
		if err := encryptAndSend(enc, []byte(line)); err != nil {
			break
		}
	}
}
