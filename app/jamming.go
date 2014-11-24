package app

import (
	"encoding/hex"
	"fmt"
	"time"
)

func DoSendJamming(app_dl_chan, app_ul_chan chan []byte) {
	ED := byte(0)
	base_payload := []byte{0x00, 0x01, // battery voltage
		0x00, 0x10} // temperature

LOOP:
	for {
		select {
		case <-time.Tick(5 * time.Second):
			payload := append(base_payload, ED)
			ED += 1
			app_ul_chan <- payload
			fmt.Println("sent data:", hex.EncodeToString(payload))

		case _, more := <-app_dl_chan:
			if !more {
				break LOOP
			}

		}
	}
	fmt.Println("stopped sending jamming measurement data")
}
