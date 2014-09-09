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
	mtype int
	data  []byte
}

func (msg *Message) GenerateMessage() []byte {
	msglen := len(msg.data)
	buflen := msglen + 3 // add 3 for mtype, len, and csum

	buf := make([]byte, buflen)
	buf[0] = byte(msg.mtype)
	buf[1] = byte(buflen)

	if msglen > 0 {
		copy(buf[2:buflen-1], msg.data)
	}
	buf[buflen-1] = calc_checksum(buf[:buflen-1])

	return buf
}

func (msg *Message) ParseBuffer(buf []byte) error {
	buflen := len(buf)
	if buf[1] != byte(buflen) {
		return fmt.Errorf("invalid length")
	}

	csum := buf[buflen-1]
	expcsum := calc_checksum(buf[:buflen-1])
	if csum != expcsum {
		return fmt.Errorf("invalid checksum")
	}

	msg.mtype = int(buf[0])
	if msg.mtype == 3 || msg.mtype == 4 {
		msg.data = buf[2 : buflen-1]
	} else { // hello and hello ack have no content
		msg.data = []byte{}
	}

	return nil
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
	var csum = byte(0xff)
	for i := range data {
		csum -= data[i]
	}
	return csum
}

func receive_with_timeout(rxch <-chan []byte, timeout time.Duration) ([]byte, error) {
	select {
	case <-time.After(timeout * time.Second):
		return nil, fmt.Errorf("serial read timeout")

	case buf := <-rxch:
		return buf, nil
	}
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
			msg := Message{mtype: 1, data: []byte{0xde, 0xad, 0xbe, 0xef}}
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

	serial := SerialReader{s}
	rxch := utils.MakeChannel(serial)

	// handshake
	hello := Message{1, []byte{}}
	msg_hello := hello.GenerateMessage()
	s.Write(msg_hello)
	buf, err := receive_with_timeout(rxch, 10)
	if err != nil {
		fmt.Println("error reading serial handshake:", err.Error())
		os.Exit(1)
	}
	rcvd := Message{}
	rcvd.ParseBuffer(buf)
	if rcvd.mtype != 2 {
		fmt.Println("invalid hello ack")
		os.Exit(1)
	}

	// automatic serial sender just for testing
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

				close(ul_chan)
				break LOOP
			}

			msg := Message{mtype: 3, data: data}
			buf := msg.GenerateMessage()
			s.Write(buf)
			fmt.Println("written to serial:", hex.EncodeToString(buf))

		case buf := <-rxch:
			if len(buf) == 0 {
				continue
			}

			rcvd := Message{}
			err := rcvd.ParseBuffer(buf)
			if err != nil {
				fmt.Println("error parsing buffer:", err.Error())
				continue
			}

			switch rcvd.mtype {
			case 1, 2:
				continue

			case 3:
				ul_chan <- rcvd.data

			case 4:
				fmt.Println("received debug message:", hex.EncodeToString(rcvd.data))

			}
		}
	}
	fmt.Println("serial worker stopped")
}
