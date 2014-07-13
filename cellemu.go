package main

import (
	"fmt"
	work "github.com/herrfz/cellemu/worker"
	zmq "github.com/pebbe/zmq4"
)

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

	data_ch := makeChannel(d_dl_sock)
	cmd_ch := makeChannel(c_sock)

	for {
		select {
		case d1 := <-cmd_ch:
			// TCP strangely sends [] when ending message
			if len(d1) == 0 {
				continue
			}
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

func makeChannel(sock *zmq.Socket) <-chan []byte {
	c := make(chan []byte)
	go func() {
		for {
			buf, _ := sock.Recv(0)
			c <- []byte(buf)
		}
	}()
	return c
}
