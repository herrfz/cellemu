package app

import (
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
	buf := make([]byte, 1)
	lsr := make([]byte, 18)
	header := make([]byte, 18) // header := packet header until the space after check string
	state := 0
	checkString := "< N F C > "

	for {
		_, err := s.serial.Read(buf)
		if err != nil {
			return []byte{}, err
		}

		for i := 17; i > 0; i-- { // most recent byte pushes register to the left
			lsr[i] = lsr[i-1]
		}
		lsr[0] = buf[0]

		if buf[0] == checkString[state] {
			state++
			if state == 10 {
				// construct packet and return
				remLen := 2*int(lsr[17]) - 16 // times two to take the whitespaces into account
				rest := make([]byte, remLen)
				_, err := s.serial.Read(rest)
				if err != nil {
					return []byte{}, err
				} else {
					for i := 0; i < 18; i++ {
						header[i] = lsr[18-i-1]
					}
					return append(header, rest...), nil
				}

			} else { // going well but not at state 5 yet, read further
				continue
			}

		} else { // read-byte not in check string, continue reading (exhaust the buffer)
			state = 0
			continue
		}
	}
}

func DoForwardData(appDlCh, appUlCh chan []byte, device string) {
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
			appUlCh <- payload
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
