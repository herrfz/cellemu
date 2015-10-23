package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/herrfz/coordnode/app"
	work "github.com/herrfz/coordnode/worker"
	"github.com/herrfz/devreader"
	"github.com/tarm/goserial"
	"io"
	"os"
	"os/signal"
	"strings"
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

type AppFunction func(chan []byte, chan []byte)

const QSIZE = 10

func main() {
	nodeserial := flag.String("nodeserial", "", "serial device to connect to node")
	wdcserial := flag.String("wdcserial", "", "serial device to connect to wdc")
	apps := flag.String("apps", "", "list of applications, comma separated")
	addr := flag.String("addr", "0000", "short address, two bytes little endian in hex")
	master := flag.Bool("master", false, "set as master node that replies to handshake messages")
	secure := flag.Bool("sec", true, "use security features")
	flag.Parse()

	if *nodeserial == "" && *wdcserial == "" {
		fmt.Println("no serial device provided")
		os.Exit(1)
	}

	listapps := strings.Split(*apps, ",")
	b_addr, _ := hex.DecodeString(*addr)

	dl_chan := make(chan []byte)
	ul_chan := make(chan []byte)
	app_dl_chan := make(chan []byte)        // no buffered channel, used only for broadcast close
	app_ul_chan := make(chan []byte, QSIZE) // use buffered channel for multiple apps

	// map string argument with the corresponding app function
	mapapps := make(map[string]AppFunction)
	mapapps["jamming"] = app.DoSendJamming
	mapapps["temperature"] = app.DoSendTemperature

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	siface := &serial.Config{Name: *wdcserial, Baud: 9600}
	s, err := serial.OpenPort(siface)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	defer s.Close()

	ser := SerialReader{s}
	wdcch := devreader.MakeChannel(ser)

	if *nodeserial != "" {
		go work.DoSerialDataRequest(dl_chan, ul_chan, *nodeserial)
	} else {
		go work.DoDataRequest(b_addr, dl_chan, ul_chan, app_dl_chan, app_ul_chan, *secure)
	}

	// iterate over apps and start the corresponding goroutine
	for _, a := range listapps {
		fun := mapapps[a]
		if fun != nil {
			go fun(app_dl_chan, app_ul_chan)
		}
	}

LOOP:
	for {
		select {
		case wdc_req := <-wdcch:
			wdc_res := work.ProcessMessage(wdc_req)
			if wdc_res != nil && *master {
				// TODO: add mutex
				s.Write(wdc_res)
				fmt.Println("sent answer to WDC request")
			}
			// if buf is MAC_DATA_REQUEST, pass it to handler goroutine
			// can either be local handler or serial forwarder
			if len(wdc_req) != 0 && wdc_req[1] == 0x17 {
				reqmsg := work.WDC_REQ{}
				reqmsg.ParseWDCReq([]byte(wdc_req))
				if bytes.Equal(reqmsg.DSTADDR, b_addr) { // only process message that is sent to us
					dl_chan <- []byte(wdc_req)
				}
			}

		case node_ind := <-ul_chan:
			// TODO: add mutex
			s.Write(node_ind)
			fmt.Println("sent node uplink message")

		case <-c:
			close(app_dl_chan)
			close(dl_chan)
			<-ul_chan
			break LOOP
		}
	}
	fmt.Println("Program stopped")
}
