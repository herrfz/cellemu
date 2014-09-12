package worker

import (
	"encoding/hex"
	"fmt"
	msg "github.com/herrfz/gowdc/messages"
)

func process_message(buf []byte) []byte {
	var retmsg []byte
	if len(buf) == 0 {
		dummy := make([]byte, 0)
		retmsg = dummy
	}

	switch buf[1] {
	case 0x01:
		fmt.Println("received CoordNode connect")
		fake := []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
		copy(msg.WDC_CONNECTION_RES[2:], fake)
		fmt.Println("CoordNode connection created")
		retmsg = msg.WDC_CONNECTION_RES

	case 0x03:
		fmt.Println("received CoordNode disconnect")
		fmt.Println("CoordNode disconnected")
		retmsg = msg.WDC_DISCONNECTION_REQ_ACK

	case 0x07:
		fmt.Println("received set CorrdNode long address")
		fmt.Println("CorrdNode long address set")
		retmsg = msg.WDC_SET_COOR_LONG_ADDR_REQ_ACK

	case 0x09:
		fmt.Println("received reset command")
		fmt.Println("CoordNode reset")
		retmsg = msg.WDC_RESET_REQ_ACK

	case 0x10:
		fmt.Println("received WDC sync")
		fmt.Println("WDC sync-ed")
		retmsg = nil

	case 0x11: // start TDMA
		fmt.Println("received start TDMA:", hex.EncodeToString(buf))
		msg.WDC_GET_TDMA_RES[2] = 0x01 // running
		copy(msg.WDC_GET_TDMA_RES[3:], buf[2:])
		msg.WDC_ACK[1] = 0x12 // START_TDMA_REQ_ACK
		fmt.Println("TDMA started")
		retmsg = msg.WDC_ACK

	case 0x13: // stop TDMA
		fmt.Println("received stop TDMA")
		msg.WDC_GET_TDMA_RES[2] = 0x00 // stopped
		msg.WDC_ACK[1] = 0x14          // STOP_TDMA_REQ_ACK
		fmt.Println("TDMA stopped")
		retmsg = msg.WDC_ACK

	case 0x15: // TDMA status
		fmt.Println("received TDMA status request")
		fmt.Println("sent TDMA status response:", hex.EncodeToString(msg.WDC_GET_TDMA_RES))
		retmsg = msg.WDC_GET_TDMA_RES

	case 0x17: // data request
		fmt.Println("received data request", hex.EncodeToString(buf))

		// send confirmation
		msg.WDC_MAC_DATA_CON[2] = buf[2]
		msg.WDC_MAC_DATA_CON[3] = 0x00 // success
		fmt.Println("sent data confirmation", hex.EncodeToString(msg.WDC_MAC_DATA_CON))
		retmsg = msg.WDC_MAC_DATA_CON

	default:
		fmt.Println("received wrong cmd")
		// send back WDC_ERROR
		msg.WDC_ERROR[2] = byte(msg.WRONG_CMD)
		retmsg = msg.WDC_ERROR
	}
	return retmsg
}
