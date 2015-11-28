package app

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/herrfz/devreader"
	"github.com/tarm/goserial"
	"io"
	"os"
)

type SerialReader struct {
	serial io.ReadWriteCloser
}

func (s SerialReader) ReadDevice() ([]byte, error) {
	BUFSIZE := 27 // 1B length, 2B header, 1B seq nr, 5B <NFC>. each byte translates into three characters: 2chr hex + space
	buf := make([]byte, 1)
	lsr := make([]byte, BUFSIZE)
	header := make([]byte, BUFSIZE) // header := packet header until the space after check string
	state := 0
	checkString := "3C 4E 46 43 3E " // the string "< N F C > " in hex
	endState := len(checkString)

	for {
		_, err := s.serial.Read(buf)
		if err != nil {
			return []byte{}, err
		}

		for i := BUFSIZE - 1; i > 0; i-- { // most recent byte pushes register to the left
			lsr[i] = lsr[i-1]
		}
		lsr[0] = buf[0]

		if buf[0] == checkString[state] {
			state++
			if state == endState {
				// construct packet and return
				lengthBytes := []byte{lsr[BUFSIZE-1], lsr[BUFSIZE-2]}
				tempLen, _ := hex.DecodeString(string(lengthBytes))
				remLen := 3*int(tempLen[0]) - 24 // times three to take the ascii encoding, i.e. one byte is encoded as two character ascii (e.g. 18 is a one and an eight), and the whitespaces into account
				rest := make([]byte, remLen)
				_, err := s.serial.Read(rest)
				if err != nil {
					return []byte{}, err
				} else {
					for i := 0; i < BUFSIZE; i++ {
						header[i] = lsr[BUFSIZE-i-1]
					}
					packetString := append(header, rest...)
					var packet bytes.Buffer
					for i := 0; i < len(packetString); i++ {
						if i%3 != 2 { // remove every third character; it's a space
							packet.WriteByte(packetString[i])
						}
					}
					ret, _ := hex.DecodeString(packet.String())
					return ret, nil
				}

			} else { // going well but not at end state yet, read further
				continue
			}

		} else { // read-byte not in check string, continue reading (exhaust the buffer)
			state = 0
			continue
		}
	}
}

func DoForwardData(appDlCh, appUlCh, crossCh chan []byte, device string) {
	siface := &serial.Config{Name: device, Baud: 57600}
	serReader, err := serial.OpenPort(siface)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	defer serReader.Close()
	ser := SerialReader{serReader}
	serCh := devreader.MakeChannel(ser)

LOOP:
	for {
		select {
		case payload := <-serCh:
			crossCh <- payload
			fmt.Printf("read nfc data\n- ascii: %s\n- hex: %x\n", string(payload), string(payload))

		case _, more := <-appDlCh:
			if !more {
				close(appUlCh)
				break LOOP
			}
		}
	}
	fmt.Println("stopped forwarding nfc data")
}
