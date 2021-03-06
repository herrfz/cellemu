// This package implements workers for external components
package worker

import (
	"encoding/hex"
	"fmt"
	"github.com/herrfz/devreader"
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
	buf[buflen-1] = calcChecksum(buf[:buflen-1])

	return buf
}

func (msg *Message) ParseBuffer(buf []byte) error {
	buflen := len(buf)
	if buflen == 0 {
		return fmt.Errorf("received zero length message")
	}

	if buf[1] != byte(buflen) {
		return fmt.Errorf("invalid length")
	}

	csum := buf[buflen-1]
	expcsum := calcChecksum(buf[:buflen-1])
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
	buf := make([]byte, 1)
	ret := make([]byte, 128)

	i := 0
	_, err := s.serial.Read(buf) // read one byte at a time
	if err == nil {
		ret[i] = buf[0] // first byte is ID
		i++

		s.serial.Read(buf)
		ret[i] = buf[0] // next byte is length
		lenInMsg := int(buf[0])
		i++

		var mlen int
		if lenInMsg < 128 { // never trust input
			mlen = lenInMsg
		} else {
			mlen = 128 // limit mlen to avoid overflow
		}

		for j := i; j < mlen; j++ { // the rest is payload
			s.serial.Read(buf)
			ret[j] = buf[0]
		}

		return ret[:mlen], nil

	} else {
		return []byte{}, err
	}
}

func calcChecksum(data []byte) byte {
	var csum = byte(0xff)
	for i := range data {
		csum -= data[i]
	}
	return csum
}

func receiveWithTimeout(rxch <-chan []byte, timeout time.Duration) ([]byte, error) {
	select {
	case <-time.After(timeout * time.Second):
		return nil, fmt.Errorf("serial read timeout")

	case buf := <-rxch:
		return buf, nil
	}
}

// FOR LOOPBACK TESTING ONLY, simply exits when device not available
// TODO: hard code path
func testWriteSerial(stopch chan bool) {
	c := &serial.Config{Name: "/dev/pts/4", Baud: 9600}
	s, err := serial.OpenPort(c)
	if err != nil {
		fmt.Println("error opening loopback test serial interface:", err.Error())
		close(stopch)
		return
	}
	defer s.Close()

	serial := SerialReader{s}
	testrxch := devreader.MakeChannel(serial)

LOOP:
	for {
		select {
		case <-stopch:
			break LOOP

		case buf := <-testrxch:
			if len(buf) == 0 {
				continue
			}

			rcvd := Message{}
			err := rcvd.ParseBuffer(buf)
			if err != nil {
				fmt.Println("error parsing buffer:", err.Error())
				debug := Message{4, buf}
				msgDebug := debug.GenerateMessage()
				s.Write(msgDebug)
				continue
			}

			switch rcvd.mtype {
			case 1:
				helloAck := Message{2, []byte{}}
				msgHelloAck := helloAck.GenerateMessage()
				s.Write(msgHelloAck)

				test := Message{4, []byte{0xde, 0xad, 0xca, 0xfe}}
				msgTest := test.GenerateMessage()
				s.Write(msgTest)

			case 2:
				continue

			case 3:
				fmt.Println("received application message:", hex.EncodeToString(rcvd.data))

			case 4:
				fmt.Println("received debug message:", hex.EncodeToString(rcvd.data))

			}

		case <-time.After(30 * time.Second):
			msg := Message{mtype: 4, data: []byte{0xde, 0xad, 0xbe, 0xef}}
			buf := msg.GenerateMessage()
			s.Write(buf)
			fmt.Println("test: written to serial:", hex.EncodeToString(buf))
		}
	}
	fmt.Println("testWriteSerial stopped")
}

// main goroutine loop
func DoSerialDataRequest(dlCh, ulCh chan []byte, device string) {
	// trailing LQI, ED, RX status, RX slot; TODO, all zeros for now
	// I have to add one 0x00 to remove server error!! why!!
	var trail = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	c := &serial.Config{Name: device, Baud: 9600}
	s, err := serial.OpenPort(c)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	defer s.Close()

	serial := SerialReader{s}
	rxch := devreader.MakeChannel(serial)

	// automatic serial sender just for testing
	stopch := make(chan bool)
	go testWriteSerial(stopch)

	// handshake
	hello := Message{1, []byte{}}
	msgHello := hello.GenerateMessage()
	s.Write(msgHello)
	fmt.Println("sent hello:", hex.EncodeToString(msgHello), "waiting for ack...")
	buf, err := receiveWithTimeout(rxch, 10)
	fmt.Println("received hello ack:", hex.EncodeToString(buf))
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

LOOP:
	for {
		select {
		case buf, more := <-dlCh:
			if !more {
				fmt.Println("stopping serial worker...")
				close(ulCh)
				break LOOP
			}

			wdcReq := WDC_REQ{}
			wdcReq.ParseWDCReq(buf)
			if wdcReq.MSDULEN != len(wdcReq.MSDU) {
				fmt.Println("MSDU length mismatch, on frame:", wdcReq.MSDULEN, ", received:", len(wdcReq.MSDU))
				continue
			}

			MSDU := make([]byte, len(wdcReq.MSDU))
			copy(MSDU, wdcReq.MSDU) // if I don't do this the MSDU gets corrupted!?!?!?
			MPDU := MakeMPDU([]byte{0x01, 0x98}, wdcReq.DSTPAN, wdcReq.DSTADDR, []byte{0xff, 0xff}, []byte{0xff, 0xff}, MSDU)
			app := Message{mtype: 3, data: MPDU}
			msgApp := app.GenerateMessage()
			s.Write(msgApp)
			fmt.Println("written to serial:", hex.EncodeToString(msgApp))

		case buf := <-rxch:
			if len(buf) == 0 {
				continue
			}

			rcvd := Message{}
			err := rcvd.ParseBuffer(buf)
			if err != nil {
				fmt.Println("error parsing buffer:", err.Error(), hex.EncodeToString(buf))
				continue
			}

			switch rcvd.mtype {
			case 1, 2:
				continue

			case 3:
				ind := MakeWDCInd(rcvd.data, trail) // rcvd.data must be an MPDU
				ulCh <- ind

			case 4:
				fmt.Println("received debug message:", hex.EncodeToString(rcvd.data))

			}
		}
	}
	fmt.Println("serial worker stopped")
}
