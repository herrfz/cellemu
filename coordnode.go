package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/herrfz/coordnode/app"
	"github.com/herrfz/coordnode/worker"
	"github.com/herrfz/devreader"
	"github.com/tarm/goserial"
	"io"
	"os"
	"os/signal"
	"sync"
)

type SerialReader struct {
	serial io.ReadWriteCloser
}

// SerialReader defines ReadDevice, means it implements devreader interface
func (s SerialReader) ReadDevice() ([]byte, error) {
	buf := make([]byte, 128)
	msgLen, _ := s.serial.Read(buf)
	if msgLen > 0 {
		return buf[:msgLen], nil
	} else {
		return []byte{}, nil
	}
}

type appFunction func(chan []byte, chan []byte)

var chPool [](chan []byte)
var mutex = &sync.Mutex{} // protect uplink serial access to wdc; multiple node goroutines

func main() {
	nodeSerial := flag.String("nodeSerial", "", "serial device to connect to node")
	wdcSerial := flag.String("wdcSerial", "", "serial device to connect to wdc")
	nJamming := flag.Int("nJamming", 0, "number of sensors sending jamming data")
	nSensors := flag.Int("nSensors", 1, "number of sensors sending arbitrary data")
	secure := flag.Bool("sec", true, "apply security processing")
	flag.Parse()

	// check serial devices
	if *wdcSerial == "" {
		fmt.Println("serial connection to wdc is not provided")
		os.Exit(1)
	}

	// register interrupt signal
	intrCh := make(chan os.Signal)
	signal.Notify(intrCh, os.Interrupt)

	// register total nodes and corresponding handler goroutines
	mapApps := make(map[int]appFunction)
	for i := 0; i < *nJamming; i++ {
		mapApps[i] = app.DoSendJamming
	}
	for i := *nJamming; i < *nJamming+*nSensors; i++ {
		mapApps[i] = app.DoSendData
	}

	// configure serial device connecting to wdc
	siface := &serial.Config{Name: *wdcSerial, Baud: 9600}
	serReader, err := serial.OpenPort(siface)
	if err != nil {
		fmt.Println("error opening serial interface:", err.Error())
		os.Exit(1)
	}
	defer serReader.Close()
	ser := SerialReader{serReader}
	wdcCh := devreader.MakeChannel(ser)

	for addr, fun := range mapApps {
		// if nodeSerial is used, we just need one passthrough goroutine
		if *nodeSerial != "" {
			dlCh := make(chan []byte)
			ulCh := make(chan []byte)
			go worker.DoSerialDataRequest(dlCh, ulCh, *nodeSerial)
			break
		}

		// otherwise, start one goroutine per node
		go func(addr int, fun appFunction) {
			coord := false
			if addr == 0 {
				// first node shall be coordinator
				coord = true
			}

			nodeAddr := make([]byte, 2)
			binary.BigEndian.PutUint16(nodeAddr, uint16(addr))

			// channels for node's processing goroutine
			dlCh := make(chan []byte)
			ulCh := make(chan []byte)
			chPool = append(chPool, ulCh)

			// channels for node's application goroutine
			appDlCh := make(chan []byte)
			appUlCh := make(chan []byte)

			go fun(appDlCh, appUlCh)
			go worker.DoDataRequest(nodeAddr, dlCh, ulCh, appDlCh, appUlCh, *secure)

		LOOP:
			for {
				select {
				case wdcReq, more := <-wdcCh:
					if !more {
						close(dlCh)
						<-ulCh
						break LOOP
					}

					if coord {
						wdcRes := worker.ProcessMessage(wdcReq)
						if wdcRes != nil {
							mutex.Lock()
							serReader.Write(wdcRes)
							mutex.Unlock()
							fmt.Println("sent answer to WDC request")
						}
					}
					// if MAC_DATA_REQUEST, pass it to node's processing goroutine
					// can either be local handler or serial forwarder
					if len(wdcReq) != 0 && wdcReq[1] == 0x17 {
						reqmsg := worker.WDC_REQ{}
						reqmsg.ParseWDCReq([]byte(wdcReq))
						if bytes.Equal(reqmsg.DSTADDR, nodeAddr) { // only process message that is sent to us
							dlCh <- []byte(wdcReq)
						}
					}

				case nodeInd := <-ulCh:
					mutex.Lock()
					serReader.Write(nodeInd)
					mutex.Unlock()
					fmt.Println("sent node uplink message")
				}
			}
			fmt.Println("node stopped")
		}(addr, fun)
	}

MAINLOOP:
	for {
		select {
		case <-intrCh:
			close(wdcCh)
			for idx := range chPool {
				<-chPool[idx]
			}
			break MAINLOOP
		}
	}
	fmt.Println("program stopped")
}
