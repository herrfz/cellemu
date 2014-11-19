package app

import (
	"encoding/hex"
	"fmt"
	"time"
)

func DoSendJamming(app_dl_chan, app_ul_chan chan []byte, interval time.Duration) {
	payload := []byte{0x00, 0x01, // battery voltage
		0x00, 0x10, // temperature
		0xe0} // ED

LOOP:
	for {
		select {
		case <-time.Tick(interval * time.Second):
			app_ul_chan <- payload
			fmt.Println("sent data:", hex.EncodeToString(payload))

		case _, more := <-app_dl_chan:
			if !more {
				close(app_ul_chan)
				break LOOP
			}

		}
	}
	fmt.Println("stopped sending jamming measurement data")
}
