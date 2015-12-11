package app

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func DoSendJamming(appDlCh, appUlCh, crossCh chan []byte, device string) {
	ED := byte(0)
	basePayload := []byte{0x00, 0x01, // battery voltage
		0x00, 0x10} // temperature

LOOP:
	for {
		select {
		case <-time.Tick(time.Duration(rand.Intn(5)) + 7*1000*time.Millisecond): // add 5ms jitter
			payload := append(basePayload, ED)
			ED += 1
			appUlCh <- payload
			fmt.Println("sent jamming data:", hex.EncodeToString(payload))

		case _, more := <-appDlCh:
			if !more {
				close(appUlCh)
				break LOOP
			}
		}
	}
	fmt.Println("stopped sending jamming measurement data")
}
