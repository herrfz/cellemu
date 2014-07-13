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
	ul_chan_2 := make(chan []byte)

	go work.EmulCoordNode(dl_chan, ul_chan, ul_chan_2)

	go func() {
		for {
			buf, _ := c_sock.Recv(0)
			dl_chan <- []byte(buf)

			dbuf := <-ul_chan
			c_sock.Send(string(dbuf), 0)
			fmt.Println("sent answer to TCP command")
		}
	}()

	go func() {
		for {
			buf, _ := d_dl_sock.Recv(0)
			dl_chan <- []byte(buf)

			dbuf := <-ul_chan
			d_ul_sock.Send(string(dbuf), 0)
			fmt.Println("sent answer to UDP mcast message")
		}
	}()

	go func() {
		for {
			dbuf := <-ul_chan_2
			d_ul_sock.Send(string(dbuf), 0)
			fmt.Println("sent node uplink message")
		}
	}()

	select {}
}
