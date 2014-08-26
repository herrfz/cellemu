// This package implements workers for external components
package worker

import (
	"github.com/tarm/goserial"
	"io"
)

func DoSerial(dl_chan, ul_chan chan []byte) {
	c := &serial.Config{Name: "/dev/tty0", Baud: 57600}
	s, err := serial.OpenPort(c)
	if err != nil {
		panic(err) // TODO
	}

	go read_from_serial(s, ul_chan)
	go write_to_serial(dl_chan, s)
}

func read_from_serial(s io.ReadWriteCloser, ul_chan chan []byte) {
	for {
		buf := make([]byte, 128)
		n, err := s.Read(buf)
		if err != nil {
			panic(err) // TODO
		}
		ul_chan <- buf[:n]
	}
}

func write_to_serial(dl_chan chan []byte, s io.ReadWriteCloser) {
	for {
		buf := <-dl_chan
		_, err := s.Write(buf)
		if err != nil {
			panic(err) // TODO
		}
	}
}
