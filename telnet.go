package main

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"os"

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
