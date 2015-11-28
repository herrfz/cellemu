package app

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func DoSendData(appDlCh, appUlCh, crossCh chan []byte, device string) {
	sPayload := "a001000008ad000017700000000000000000c6e0" // cf. AED temperature test app
	payload, _ := hex.DecodeString(sPayload)

LOOP:
	for {
		select {
		case <-time.Tick(time.Duration(rand.Intn(5)) + 5*1000*time.Millisecond): // add 5ms jitter
			appUlCh <- payload
			fmt.Println("sent sensor data:", sPayload)

		case _, more := <-appDlCh:
			if !more {
				close(appUlCh)
				break LOOP
			}
		}
	}
	fmt.Println("stopped sending sensor data")
}
