package worker

import (
	"encoding/hex"
	"fmt"
	//"github.com/herrfz/coordnode/crypto/hmac"
	"time"
)

func DoSendJamming(dl_chan, ul_chan chan []byte) {
	// LQI (1), ED (1), RXstatus (1), RXslot (2)
	var trail = []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	//var SIK = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	//	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	sensor_addr := []byte{0x1c, 0xaa, // sensor PAN
		0x00, 0x00} // sensor address
	wdc_addr := []byte{0xff, 0xff, // WDC PAN
		0xff, 0xff} // WDC address

	MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
		0x00} // sequence number, must be set to zero
	MHR = append(MHR, append(wdc_addr, sensor_addr...)...)
	MSDU_HEADER := []byte{0x09} // security, unicast mID
	//	[]byte{0x00, 0x00, 0x00, 0x00}...) // security, sequence number, ignored for now
	// payload
	MSDU_PAYLOAD := []byte{0x00, 0x01, // battery voltage
		0x00, 0x10, // temperature
		0xe0} // ED

	MPDU := append(MHR, append(MSDU_HEADER, MSDU_PAYLOAD...)...)

	//msgMAC := hmac.SHA256HMACGenerate(SIK, MPDU) // security, no encryption, just MAC
	MFR := []byte{0xde, 0xad} // FCS, 16-bit CRC <--fake
	//PSDU := append(MPDU, append(msgMAC, MFR...)...)
	PSDU := append(MPDU, MFR...)
	IND := MakeWDCInd(PSDU, trail)

LOOP:
	for {
		select {
		case <-time.Tick(2 * time.Second):
			ul_chan <- IND
			fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

		case _, more := <-dl_chan:
			if !more {
				//close(ul_chan)
				break LOOP
			}

		}
	}
	fmt.Println("stopped sending jamming measurement data")
}
