package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/herrfz/coordnode/app"
	work "github.com/herrfz/coordnode/worker"
	"github.com/herrfz/devreader"
	zmq "github.com/pebbe/zmq4"
	"os"
	"os/signal"
	"strings"
)

type Socket struct {
	socket *zmq.Socket
}

func (sock Socket) ReadDevice() ([]byte, error) {
	buf, err := sock.socket.Recv(0)
	if err != nil {
		if err.Error() == "Operation cannot be accomplished in current state" {
			// give some time for REP socket to send before another recv
			return nil, fmt.Errorf("DONTPANIC")
		}
	}
	return []byte(buf), err
}

type AppFunction func(chan []byte, chan []byte)

const QSIZE = 10

func main() {
	serial := flag.Bool("serial", false, "use serial port to talk to sensor node")
	device := flag.String("device", "", "serial device to use")
	apps := flag.String("apps", "", "list of applications, comma separated")
	addr := flag.String("addr", "0000", "short address, two bytes little endian in hex")
	master := flag.Bool("master", false, "set as master node that replies to handshake messages")
	secure := flag.Bool("sec", true, "use security features")
	flag.Parse()

	if *serial && *device == "" {
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

	c_sock, _ := zmq.NewSocket(zmq.REP)
	defer c_sock.Close()
	c_sock.Bind("tcp://*:5555")

	d_dl_sock, _ := zmq.NewSocket(zmq.SUB) // SUB
	defer d_dl_sock.Close()
	d_dl_sock.Connect("tcp://127.0.0.1:5556")
	d_dl_sock.SetSubscribe("") // subscribe to all (?) TODO: subscribe to addr

	d_ul_sock, _ := zmq.NewSocket(zmq.PUSH) // PUB
	defer d_ul_sock.Close()
	d_ul_sock.Connect("tcp://127.0.0.1:5557")

	if *serial {
		go work.DoSerialDataRequest(dl_chan, ul_chan, *device)
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

	data_ch := devreader.MakeChannel(Socket{d_dl_sock})
	cmd_ch := devreader.MakeChannel(Socket{c_sock})

LOOP:
	for {
		select {
		case buf := <-cmd_ch:
			respmsg := work.ProcessMessage([]byte(buf))
			if respmsg != nil && *master {
				c_sock.Send(string(respmsg), 0)
				fmt.Println("sent answer to TCP command")
			}

		case buf := <-data_ch:
			fmt.Println("received from downlink channel")
			respmsg := work.ProcessMessage([]byte(buf))
			if respmsg != nil && *master {
				d_ul_sock.Send(string(respmsg), 0)
				fmt.Println("sent answer to UDP mcast message")
			}
			// if buf is MAC_DATA_REQUEST, pass it to handler goroutine
			// can either be local handler or serial forwarder
			if len(buf) != 0 && buf[1] == 0x17 {
				reqmsg := work.WDC_REQ{}
				reqmsg.ParseWDCReq([]byte(buf))
				if bytes.Equal(reqmsg.DSTADDR, b_addr) { // only process message that is sent to us
					dl_chan <- []byte(buf)
				}
			}

		case buf := <-ul_chan:
			d_ul_sock.Send(string(buf), 0)
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
