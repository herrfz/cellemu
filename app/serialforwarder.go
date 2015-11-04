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
			return append(buf, ret...), nil // rejoin length field and the rest
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
			fmt.Println("forward sensor data:", hex.EncodeToString(payload))

		case _, more := <-appDlCh:
			if !more {
				close(appUlCh)
				break LOOP
			}
		}
	}
	fmt.Println("stopped forwarding sensor data")
}
