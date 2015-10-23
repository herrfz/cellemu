package app

import (
	"encoding/hex"
	"fmt"
	"time"
)

func DoSendTemperature(app_dl_chan, app_ul_chan chan []byte) {
	s_payload := "a001000008ad000017700000000000000000c6e0" // cf. AED temperature test app
	payload, _ := hex.DecodeString(s_payload)

LOOP:
	for {
		select {
		case <-time.Tick(5 * time.Second):
			app_ul_chan <- payload
			fmt.Println("sent temperature data:", s_payload)

		case _, more := <-app_dl_chan:
			if !more {
				break LOOP
			}

		}
	}
	fmt.Println("stopped sending temperature measurement data")
}
