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
	msgLen, err := s.serial.Read(buf)
	if msgLen > 0 && err == nil {
		return buf[:msgLen], nil
	} else {
		return []byte{}, err
	}
}

type node struct {
	appFunction func(appDlCh, appUlCh, crossCh chan []byte, device string)
	device      string
}

var nodeWdcChannels, chPool [](chan []byte)
var mutex = &sync.Mutex{} // protect uplink serial access to wdc; multiple node goroutines

func main() {
	nodeSerial := flag.String("nodeSerial", "", "serial device to connect to node")
	wdcSerial := flag.String("wdcSerial", "", "serial device to connect to wdc")
	fwdSerial := flag.String("fwdSerial", "", "serial device to read and forward data from a real node") // TODO: enable list of serial interfaces
	nJamming := flag.Int("nJamming", 0, "number of sensors sending jamming data")
	nSensors := flag.Int("nSensors", 0, "number of sensors sending arbitrary data")
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
	mapNodes := make(map[int]node)
	for i := 0; i < *nJamming; i++ {
		mapNodes[i] = node{app.DoSendJamming, ""}
	}
	for i := *nJamming; i < *nJamming+*nSensors; i++ {
		mapNodes[i] = node{app.DoSendData, ""}
	}
	if *fwdSerial != "" {
		mapNodes[*nJamming+*nSensors] = node{app.DoForwardData, *fwdSerial}
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

	for addr, curnode := range mapNodes {
		// if nodeSerial is used, we just need one passthrough goroutine
		if *nodeSerial != "" {
			dlCh := make(chan []byte)
			ulCh := make(chan []byte)
			go worker.DoSerialDataRequest(dlCh, ulCh, *nodeSerial)
			break
		}

		// otherwise, start one goroutine per node
		go func(addr int, curnode node) {
			nodeAddr := make([]byte, 2)
			binary.LittleEndian.PutUint16(nodeAddr, uint16(addr))

			// channel for receiving wdc message
			nodeWdcCh := make(chan []byte)
			nodeWdcChannels = append(nodeWdcChannels, nodeWdcCh)

			// channels for node's processing goroutine
			dlCh := make(chan []byte)
			ulCh := make(chan []byte)
			chPool = append(chPool, ulCh)

			// channels for node's application goroutine
			appDlCh := make(chan []byte)
			appUlCh := make(chan []byte)

			// channel for sharing data between worker and app
			crossCh := make(chan []byte)

			go curnode.appFunction(appDlCh, appUlCh, crossCh, curnode.device)
			go worker.DoDataRequest(nodeAddr, dlCh, ulCh, appDlCh, appUlCh, crossCh, *secure)

		LOOP:
			for {
				select {
				case wdcReq, more := <-nodeWdcCh:
					if !more {
						close(dlCh)
						break LOOP
					}

					reqmsg := worker.WDC_REQ{}
					reqmsg.ParseWDCReq([]byte(wdcReq))
					if bytes.Equal(reqmsg.DSTADDR, nodeAddr) || bytes.Equal(reqmsg.DSTADDR, []byte{0xff, 0xff}) { // only process message that is sent to us or broadcast
						dlCh <- []byte(wdcReq)
					}

				case nodeInd := <-ulCh:
					mutex.Lock()
					serReader.Write(nodeInd) // ignore error on wdc serial write
					mutex.Unlock()
					fmt.Println("sent node uplink message")
				}
			}
			fmt.Println("node stopped")
		}(addr, curnode)
	}

MAINLOOP:
	for {
		select {
		case wdcReq := <-wdcCh:
			go func() { // process wdc message in a separate goroutine
				wdcRes := worker.ProcessMessage(wdcReq)
				if wdcRes != nil {
					mutex.Lock()
					serReader.Write(wdcRes) // ignore error on wdc serial write
					mutex.Unlock()
					fmt.Println("sent answer to WDC request")
				}
			}()

			// if MAC_DATA_REQUEST, pass it to node goroutines
			if len(wdcReq) != 0 && wdcReq[1] == 0x17 {
				for _, ch := range nodeWdcChannels {
					ch <- wdcReq
				}
			}

		case <-intrCh:
			for idx := range nodeWdcChannels {
				close(nodeWdcChannels[idx])
				<-chPool[idx]
			}
			break MAINLOOP
		}
	}
	fmt.Println("program stopped")
}
