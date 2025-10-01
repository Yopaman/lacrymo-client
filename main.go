package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/markdingo/netstring"
	"github.com/pkg/term"
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
	var hostname = flag.String("h", "lacrymo.tme-crypto.fr", "Server hostname")
	var port = flag.String("p", "6025", "Server port")
	var privateKey = flag.String("sk", "./private-key.pem", "Private key")
	var serverPublicKey = flag.String("pk", "./server-public-key.pem", "Server public key")
	var username = flag.String("u", "pablo.hardouin", "Username")

	flag.Parse()

	conn, err := net.Dial("tcp", *hostname+":"+*port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	enc := netstring.NewEncoder(conn)
	dec := netstring.NewDecoder(conn)

	diffieHellman(enc, dec, *privateKey, *serverPublicKey, *username)

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

	term, err := term.Open("/dev/tty")
	if err != nil {
		panic("term open error")
	}
	term.SetCbreak()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go handleTelnet(dec, enc)

	go func() {
		<-ctx.Done()
		cmd := exec.Command("reset")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
		println("\nReceived SIGTERM. Stopping.")
		term.Restore()
		os.Exit(0)
	}()

	// Send stdin inputs to the server
	sendLoop(enc)
}
