// This package implements workers for external components
package worker

import (
	"encoding/hex"
	"fmt"
	"github.com/tarm/goserial"
	"io"
	"os"
)

func DoSerial(dl_chan, ul_chan chan Message, device string) {
	c := &serial.Config{Name: device, Baud: 9600}
	s, err := serial.OpenPort(c)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	defer s.Close()

	go read_from_serial(s, ul_chan)
	go write_to_serial(dl_chan, s)
}

func read_from_serial(s io.ReadWriteCloser, ul_chan chan Message) {
	for {
		buf := make([]byte, 128)
		n, err := s.Read(buf)
		if err != nil {
			fmt.Println("error reading from serial:", err.Error())
			continue
		}
		send_msg := Message{1, buf[:n]}
		ul_chan <- send_msg
		fmt.Println("read from serial:", hex.EncodeToString(buf[:n]))
	}
}

func write_to_serial(dl_chan chan Message, s io.ReadWriteCloser) {
	for {
		rcv_msg := <-dl_chan
		buf := rcv_msg.msg
		_, err := s.Write(buf)
		if err != nil {
			fmt.Println("error writing to serial:", err.Error())
			continue
		}
		fmt.Println("written to serial:", hex.EncodeToString(buf))
	}
}
