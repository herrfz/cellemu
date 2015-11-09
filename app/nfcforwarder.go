package app

import (
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
	buf := make([]byte, 1)
	_, err := s.serial.Read(buf)
	msgLen := int(buf[0])         // first byte is length
	if msgLen > 0 && err == nil { // no max length checking here...
		ret := make([]byte, msgLen)
		_, err = s.serial.Read(ret) // read as many bytes as length
		if err == nil {
			msg := append(buf, ret...)               // rejoin length field and the rest
			nfc, _ := hex.DecodeString("3C4E46433E") // the string "<NFC>"
			j := 4                                   // the check string <NFC> starts on byte 4 (5th byte from start)
			for _, c := range nfc {
				if c != msg[j] {
					return []byte{}, fmt.Errorf("DONTPANIC") // return early with non-critical error if check string fails
				}
				j++
			}
			return msg, nil // if check string passes, return msg
		} else {
			return []byte{}, err
		}
	} else {
		return []byte{}, err
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
			fmt.Println("forward sensor data:", string(payload))

		case _, more := <-appDlCh:
			if !more {
				close(appUlCh)
				break LOOP
			}
		}
	}
	fmt.Println("stopped forwarding sensor data")
}
