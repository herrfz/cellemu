package app

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func DoSendData(app_dl_chan, app_ul_chan chan []byte) {
	s_payload := "a001000008ad000017700000000000000000c6e0" // cf. AED temperature test app
	payload, _ := hex.DecodeString(s_payload)

LOOP:
	for {
		select {
		case <-time.Tick(time.Duration(rand.Intn(5)) + 5*1000*time.Millisecond): // add 5ms jitter
			app_ul_chan <- payload
			fmt.Println("sent sensor data:", s_payload)

		case _, more := <-app_dl_chan:
			if !more {
				close(app_ul_chan)
				break LOOP
			}
		}
	}
	fmt.Println("stopped sending sensor data")
}
