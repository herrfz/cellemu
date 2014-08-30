// This package implements workers for external components
package worker

import (
	"encoding/hex"
	"fmt"
	"github.com/tarm/goserial"
	"io"
	"os"
	"time"
)

func DoSerial(dl_chan, ul_chan chan Message, device string) {
	c := &serial.Config{Name: device, Baud: 4800}
	s, err := serial.OpenPort(c)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	defer s.Close()

	go write_to_serial(dl_chan, s)
	go read_from_serial(s, ul_chan)
	select {} // TODO: stop channel
}

func write_to_serial(dl_chan chan Message, s io.ReadWriteCloser) {
	// TODO: remove -------
	xx := &serial.Config{Name: "/dev/ttys002", Baud: 4800}
	uu, err := serial.OpenPort(xx)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	// --------------------

	for {
		//rcv_msg := <-dl_chan
		buf := []byte{0x01, 0x04, 0xde, 0xad, 0xbe, 0xef} // rcv_msg.msg
		_, err := uu.Write(buf)                           // TODO s.Write(buf)
		if err != nil {
			fmt.Println("error writing to serial:", err.Error())
			continue
		}
		fmt.Println("written to serial:", hex.EncodeToString(buf))
		time.Sleep(5 * time.Second) // TODO: remove
	}
}

func read_from_serial(s io.ReadWriteCloser, ul_chan chan Message) {
	temp := make([]byte, 1)
	buf := make([]byte, 128)
	for {
		n, _ := s.Read(temp)
		if n > 0 {
			if temp[0] == byte(1) {
				pktlen, _ := s.Read(buf)
				fmt.Println("read from serial:", hex.EncodeToString(buf[1:pktlen])) // 1st byte is len, not needed
			}
		} else {
			continue
		}
		//send_msg := Message{1, buf[:n]}
		//ul_chan <- send_msg
	}
}

func calc_checksum(data []byte) byte {
	var csum byte
	for i := range data {
		csum ^= data[i]
	}
	return csum
}
