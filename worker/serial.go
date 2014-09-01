// This package implements workers for external components
package worker

import (
	"encoding/hex"
	"fmt"
	"github.com/herrfz/gowdc/utils"
	"github.com/tarm/goserial"
	"io"
	"os"
	"time"
)

type Message struct {
	id   int
	data []byte
}

func (msg *Message) GenerateMessage() []byte {
	csum := calc_checksum(msg.data)
	msg.data = append(msg.data, csum)
	// length is defined only on payload and checksum
	// id and length itself are not counted
	msglen := len(msg.data)

	buf := make([]byte, msglen+2) // add 2 for id and len
	buf[0] = byte(msg.id)
	buf[1] = byte(msglen)
	copy(buf[2:], msg.data)

	return buf
}

type SerialReader struct {
	serial io.ReadWriteCloser
}

func (s SerialReader) ReadDevice() ([]byte, error) {
	buf := make([]byte, 128)
	msglen, _ := s.serial.Read(buf)
	if msglen > 0 {
		return buf[:msglen], nil
	} else {
		return []byte{}, nil
	}
}

func calc_checksum(data []byte) byte {
	var csum byte
	for i := range data {
		csum ^= data[i]
	}
	return csum
}

// FOR LOOPBACK TESTING ONLY, simply exits when device not available
func test_write_serial(stopch chan bool, dl_chan chan []byte, s io.ReadWriteCloser) {
	c := &serial.Config{Name: "/dev/ttys002", Baud: 9600}
	s, err := serial.OpenPort(c)
	if err != nil {
		fmt.Println("error opening loopback test serial interface:", err.Error())
		close(stopch)
		return
	}
	defer s.Close()

LOOP:
	for {
		select {
		case <-stopch:
			break LOOP

		case <-time.After(5 * time.Second):
			msg := Message{id: 1, data: []byte{0xde, 0xad, 0xbe, 0xef}}
			buf := msg.GenerateMessage()
			s.Write(buf)
			fmt.Println("written to serial:", hex.EncodeToString(buf))
		}
	}
	fmt.Println("test_write_serial stopped")
}

// main goroutine loop
func DoSerial(dl_chan, ul_chan chan []byte, device string) {
	c := &serial.Config{Name: device, Baud: 4800}
	s, err := serial.OpenPort(c)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	defer s.Close()

	// if handshake, do it here, continue only when successful

	serial := SerialReader{s}
	rxch := utils.MakeChannel(serial)

	stopch := make(chan bool)
	go test_write_serial(stopch, dl_chan, s)

LOOP:
	for {
		select {
		case data, more := <-dl_chan:
			if !more {
				fmt.Println("stopping serial worker...")
				select {
				case <-stopch: // stop channel is closed, no test writer is running
					break
				default:
					stopch <- true
				}

				ul_chan <- []byte{0xff, 0xff}
				break LOOP
			}

			msg := Message{id: 1, data: data}
			buf := msg.GenerateMessage()
			s.Write(buf)
			fmt.Println("written to serial:", hex.EncodeToString(buf))

		case buf := <-rxch:
			switch buf[0] {
			case 0x01:
				//ul_chan <- buf
				fmt.Println("read from serial:", hex.EncodeToString(buf[2:])) // 1st and 2nd bytes are header

			case 0x02:
				// TODO: handle other message types

			}

		
		}
	}
	fmt.Println("serial worker stopped")
}
