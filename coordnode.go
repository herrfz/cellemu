package main

import (
	"flag"
	"fmt"
	work "github.com/herrfz/coordnode/worker"
	"github.com/herrfz/gowdc/utils"
	"github.com/tarm/goserial"
	"io"
	"os"
	"os/signal"
)

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

func main() {
	device := flag.String("device", "", "serial device to use")
	flag.Parse()

	if *device == "" {
		fmt.Println("no serial device provided")
		os.Exit(1)
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	siface := &serial.Config{Name: *device, Baud: 9600}
	s, err := serial.OpenPort(siface)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	defer s.Close()

	serial := SerialReader{s}
	wdcch := utils.MakeChannel(serial)

	dl_chan := make(chan []byte)
	ul_chan := make(chan []byte)
	go work.DoDataRequest(dl_chan, ul_chan)

LOOP:
	for {
		select {
		case buf := <-wdcch:
			respmsg := work.ProcessMessage(buf)
			if respmsg != nil {
				s.Write(respmsg)
				fmt.Println("sent answer to WDC request")
			}
			// if buf is MAC_DATA_REQUEST, pass it to handler goroutine
			if len(buf) != 0 && buf[1] == 0x17 {
				dl_chan <- buf
			}

		case buf := <-ul_chan:
			s.Write(buf)
			fmt.Println("sent node uplink message")

		case <-c:
			close(dl_chan)
			<-ul_chan
			break LOOP
		}
	}
	fmt.Println("Program stopped")
}
