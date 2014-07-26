package main

import (
	"fmt"
	work "github.com/herrfz/cellemu/worker"
	"github.com/herrfz/gowdc/utils"
	zmq "github.com/pebbe/zmq4"
)

type Socket struct {
	socket *zmq.Socket
}

func (sock Socket) Read() ([]byte, error) {
	buf, err := sock.socket.Recv(0)
	if err != nil {
		if err.Error() == "Operation cannot be accomplished in current state" {
			// give some time for REP socket to send before another recv
			return nil, fmt.Errorf("DONTPANIC")
		}
	}
	return []byte(buf), err
}

func main() {
	c_sock, _ := zmq.NewSocket(zmq.REP)
	defer c_sock.Close()
	c_sock.Bind("tcp://*:5555")

	d_dl_sock, _ := zmq.NewSocket(zmq.PULL)
	defer d_dl_sock.Close()
	d_dl_sock.Connect("tcp://localhost:5556")

	d_ul_sock, _ := zmq.NewSocket(zmq.PUSH)
	defer d_ul_sock.Close()
	d_ul_sock.Bind("tcp://*:5557")

	dl_chan := make(chan []byte)
	ul_chan := make(chan []byte)

	go work.EmulCoordNode(dl_chan, ul_chan)

	data_ch := utils.MakeChannel(Socket{d_dl_sock})
	cmd_ch := utils.MakeChannel(Socket{c_sock})

	for {
		select {
		case d1 := <-cmd_ch:
			dl_chan <- []byte(d1)
			dbuf := <-ul_chan
			c_sock.Send(string(dbuf), 0)
			fmt.Println("sent answer to TCP command")

		case d2 := <-data_ch:
			dl_chan <- []byte(d2)
			dbuf := <-ul_chan
			d_ul_sock.Send(string(dbuf), 0)
			fmt.Println("sent answer to UDP mcast message")

		case d3 := <-ul_chan:
			d_ul_sock.Send(string(d3), 0)
			fmt.Println("sent node uplink message")
		}
	}
}
