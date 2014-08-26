// This package implements workers for external components
package worker

import (
	"encoding/hex"
	"fmt"
	"github.com/tarm/goserial"
	"io"
	"os"
)

func DoSerial(dl_chan, ul_chan chan []byte) {
	c := &serial.Config{Name: "/dev/tty0", Baud: 57600}
	s, err := serial.OpenPort(c)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}

	go read_from_serial(s, ul_chan)
	go write_to_serial(dl_chan, s)
}

func read_from_serial(s io.ReadWriteCloser, ul_chan chan []byte) {
	for {
		buf := make([]byte, 128)
		n, err := s.Read(buf)
		if err != nil {
			fmt.Println("error reading from serial:", err.Error())
			continue
		}
		ul_chan <- buf[:n]
		fmt.Println("read from serial:", hex.EncodeToString(buf[:n]))
	}
}

func write_to_serial(dl_chan chan []byte, s io.ReadWriteCloser) {
	for {
		buf := <-dl_chan
		_, err := s.Write(buf)
		if err != nil {
			fmt.Println("error writing to serial:", err.Error())
			continue
		}
		fmt.Println("written to serial:", hex.EncodeToString(buf))
	}
}
