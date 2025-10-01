package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/markdingo/netstring"
)

const (
	IAC  = 0xff
	DONT = 254
	DO   = 253
	WONT = 252
	WILL = 251
	SB   = 250
	SE   = 240

	// Telnet options
	ECHO        = 1
	SGA         = 3
	TTYPE       = 24
	NAWS        = 31
	LINEMODE    = 34
	PLUGIN      = 85
	PLUGIN_DATA = 0
	PLUGIN_CODE = 1
	BINARY      = 0
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

// send helper
func send(enc *netstring.Encoder, b ...byte) {
	err := encryptAndSend(enc, b)
	if err != nil {
		panic("error encoding option")
	}
}

// handlePlugin processes a PLUGIN subnegotiation (IAC SB 85 ... IAC SE)
func handlePlugin(data []byte) {
	if len(data) == 0 {
		return
	}
	cmd := data[0]
	payload := data[1:]

	switch cmd {
	case PLUGIN_CODE:
		// Decompress zlib payload
		r, err := zlib.NewReader(bytes.NewReader(payload))
		if err != nil {
			fmt.Println("PLUGIN_CODE decompress error:", err)
			return
		}
		defer r.Close()
		// decoded, _ := io.ReadAll(r)

		// In Python version: exec(decoded)
		// In Go we do NOT execute arbitrary code.
		// f, err := os.OpenFile("/tmp/plugin-code", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		// if err != nil {
		// 	panic(err)
		// }
		//
		// defer f.Close()
		//
		// if _, err = f.WriteString(string(decoded)); err != nil {
		// 	panic(err)
		// }

	case PLUGIN_DATA:
		// Forward to dispatcher in real app
		fmt.Printf("PLUGIN_DATA received: %q\n", payload)

	default:
		fmt.Printf("PLUGIN unknown subcommand %d payload=%q\n", cmd, payload)
	}
}

// negotiate sends WILL/DO as per our policy
func negotiate(enc *netstring.Encoder, verb, opt byte) {
	switch opt {
	case SGA:
		if verb == DO {
			send(enc, IAC, WILL, SGA) // we accept SGA
		}
	case NAWS:
		if verb == DO {
			send(enc, IAC, WILL, NAWS)
			// immediately send window size (e.g. 80x24)
			send(enc, IAC, SB, NAWS, 0, 80, 0, 24, IAC, SE)
		}
	case TTYPE:
		if verb == DO {
			send(enc, IAC, WILL, TTYPE)
			// respond with terminal type
			send(enc, IAC, SB, TTYPE, 0, 'd', 'u', 'm', 'b', IAC, SE)
		}
	case LINEMODE:

		if verb == DO {
			send(enc, IAC, WONT, LINEMODE) // refuse, or implement properly
		}
	case PLUGIN:
		if verb == DO {
			send(enc, IAC, WILL, PLUGIN)
		}
	case BINARY:
		if verb == DO {
			send(enc, IAC, WILL, BINARY)
		}
	default:
		// refuse unknowns
		switch verb {
		case DO:
			send(enc, IAC, WONT, opt)
		case WILL:
			send(enc, IAC, DONT, opt)
		}
	}
}

func handleTelnet(dec *netstring.Decoder, enc *netstring.Encoder) {

	for {
		ns, err := handleNetstring(dec)
		if err != nil {
			panic(err)
		}
		decData, err := decryptData(ns)
		if err != nil {
			continue
		}

		buf := bytes.NewBuffer(decData)
		for {
			b, err := buf.ReadByte()
			if err != nil {
				if err != io.EOF {
					fmt.Fprintln(os.Stderr, "read error:", err)
				}
				return
			}
			if b == IAC {
				verb, _ := buf.ReadByte()
				if verb == IAC {
					// escaped 255
					fmt.Print(fmt.Sprint(IAC))
					continue
				}
				switch verb {
				case DO, DONT, WILL, WONT:
					opt, _ := buf.ReadByte()
					negotiate(enc, verb, opt)
				case SB:
					// collect until IAC SE
					opt, _ := buf.ReadByte()
					data := []byte{}
					for {
						ch, _ := buf.ReadByte()
						if ch == IAC {
							next, _ := buf.ReadByte()
							if next == SE {
								break
							}
							data = append(data, ch, next)
							continue
						}
						data = append(data, ch)
					}
					switch opt {
					case PLUGIN:
						handlePlugin(data)
					case TTYPE:
						// could parse TTYPE SEND here
					case NAWS:
						// parse NAWS if needed
					}
				default:
					// ignore other commands
				}
				break
			} else {
				// Not a command : bufeak the loop to print the data directly
				fmt.Print(string(decData))
				break
			}
		}
	}
}

func handleNetstring(dec *netstring.Decoder) ([]byte, error) {
	ns, err := dec.Decode()
	if err != nil {
		return nil, errors.New("Error decoding netstring : " + err.Error())
	}
	return ns, nil
}

func decryptData(data []byte) ([]byte, error) {
	msgLength := len(data) - sMac.Size()
	verifiedData := data[:msgLength]
	decData := make([]byte, msgLength)
	sStream.XORKeyStream(decData, verifiedData)
	tag := data[msgLength:]
	_, err := sMac.Write(decData)
	if err != nil {
		return nil, err
	}
	expectedMAC := sMac.Sum(nil)
	// fmt.Printf("exp : %x\n", expectedMAC)
	// fmt.Printf("tag : %x\n", tag)
	// fmt.Printf("str : %s\n", decData)
	sMac.Reset()
	if !hmac.Equal(tag, expectedMAC) {
		return nil, errors.New("mac error")
	}

	return decData, nil
}

func encryptAndSend(enc *netstring.Encoder, data []byte) error {
	encData := make([]byte, len(data))
	cStream.XORKeyStream(encData, data)
	_, err := cMac.Write(data)
	if err != nil {
		return err
	}
	tag := cMac.Sum(nil)
	cMac.Reset()
	authData := append(encData[:], tag[:]...)
	enc.Encode(netstring.NoKey, authData)
	return nil
}

type dhClientParams struct {
	Username  string          `json:"username"`
	A         json.RawMessage `json:"A"`
	Signature string          `json:"signature"`
}

type dhServerResp struct {
	B         json.Number
	Signature string
}

func ECDSASign(keyPath string, message string) string {
	// Create a temporary file for the message
	tmpFile, err := os.CreateTemp("", "msg-*.txt")
	if err != nil {
		panic(fmt.Sprintf("failed to create temp file: %v", err))
	}
	defer os.Remove(tmpFile.Name())

	// Write the message to the temp file
	if _, err := tmpFile.WriteString(message); err != nil {
		panic(fmt.Sprintf("failed to write message: %v", err))
	}
	tmpFile.Close()

	// Create a temporary file for the signature
	sigFile, err := os.CreateTemp("", "sig-*.bin")
	if err != nil {
		panic(fmt.Sprintf("failed to create temp file: %v", err))
	}
	defer os.Remove(sigFile.Name())
	sigFile.Close()

	// Run OpenSSL to sign the message
	cmd := exec.Command("openssl", "dgst", "-hex", "-sign", keyPath, "-out", sigFile.Name(), tmpFile.Name())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		panic(fmt.Sprintf("openssl sign failed: %v, %s", err, stderr.String()))
	}

	// Read the signature
	sigBytes, err := os.ReadFile(sigFile.Name())
	if err != nil {
		panic(fmt.Sprintf("failed to read signature: %v", err))
	}
	seps := strings.Split(string(sigBytes), " ")

	// Return signature as hex string
	return string(seps[1][:len(seps[1])-1])
}

func ECDSAVerify(publicKeyPath string, signature string, message string) bool {
	// Decode hex signature back to bytes
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		panic(fmt.Sprintf("invalid signature hex: %v", err))
	}

	// Temp file for message
	tmpMsg, err := os.CreateTemp("", "msg-*.txt")
	if err != nil {
		panic(fmt.Sprintf("failed to create temp file: %v", err))
	}
	defer os.Remove(tmpMsg.Name())

	if _, err := tmpMsg.WriteString(message); err != nil {
		panic(fmt.Sprintf("failed to write message: %v", err))
	}
	tmpMsg.Close()

	// Temp file for signature
	tmpSig, err := os.CreateTemp("", "sig-*.bin")
	if err != nil {
		panic(fmt.Sprintf("failed to create sig file: %v", err))
	}
	defer os.Remove(tmpSig.Name())

	if err := os.WriteFile(tmpSig.Name(), sigBytes, 0600); err != nil {
		panic(fmt.Sprintf("failed to write signature: %v", err))
	}

	// Run OpenSSL verify
	cmd := exec.Command("openssl", "dgst", "-sha256", "-verify", publicKeyPath, "-signature", tmpSig.Name(), tmpMsg.Name())
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// OpenSSL returns error for failed verification
		return false
	}

	return bytes.Contains(out.Bytes(), []byte("Verified OK"))
}

func diffieHellman(enc *netstring.Encoder, dec *netstring.Decoder, keyPath string, publicKeyPath string) {
	p, _ := new(big.Int).SetString("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16)
	g, _ := new(big.Int).SetString("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16)
	q, _ := new(big.Int).SetString("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16)

	x, _ := rand.Int(rand.Reader, q)
	A := new(big.Int).Exp(g, x, p)
	AString := A.String()
	signature := ECDSASign(keyPath, AString)
	structValue := dhClientParams{
		Username:  "pablo.hardouin",
		A:         json.RawMessage(AString),
		Signature: signature,
	}
	jsonValue, err := json.Marshal(&structValue)
	if err != nil {
		panic(err.Error())
	}
	enc.Encode(netstring.NoKey, jsonValue)
	ns, err := handleNetstring(dec)
	if err != nil {
		panic(err.Error())
	}
	var jsonResp dhServerResp
	err = json.Unmarshal(ns, &jsonResp)
	if err != nil {
		panic(err)
	}
	B, _ := new(big.Int).SetString(jsonResp.B.String(), 10)
	K := new(big.Int).Exp(B, x, p)
	KString := K.String()
	stringToVerify := AString + "," + jsonResp.B.String() + "," + "pablo.hardouin"
	if !ECDSAVerify(publicKeyPath, jsonResp.Signature, stringToVerify) {
		panic("error verifying signature")
	}
	h := sha256.New()
	h.Write([]byte(KString + "A"))
	sKaes = h.Sum(nil)
	h.Reset()
	h.Write([]byte(KString + "B"))
	sKiv = h.Sum(nil)
	h.Reset()
	h.Write([]byte(KString + "C"))
	sKmac = h.Sum(nil)
	h.Reset()
	h.Write([]byte(KString + "D"))
	cKaes = h.Sum(nil)
	h.Reset()
	h.Write([]byte(KString + "E"))
	cKiv = h.Sum(nil)
	h.Reset()
	h.Write([]byte(KString + "F"))
	cKmac = h.Sum(nil)
}

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
