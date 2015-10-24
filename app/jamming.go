package app

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func DoSendJamming(app_dl_chan, app_ul_chan chan []byte) {
	ED := byte(0)
	base_payload := []byte{0x00, 0x01, // battery voltage
		0x00, 0x10} // temperature

LOOP:
	for {
		select {
		case <-time.Tick(time.Duration(rand.Intn(5)) + 5*1000*time.Millisecond): // add 5ms jitter
			payload := append(base_payload, ED)
			ED += 1
			app_ul_chan <- payload
			fmt.Println("sent jamming data:", hex.EncodeToString(payload))

		case _, more := <-app_dl_chan:
			if !more {
				close(app_ul_chan)
				break LOOP
			}
		}
	}
	fmt.Println("stopped sending jamming measurement data")
}
