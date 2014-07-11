// This package implements workers for external components
package worker

import (
	"encoding/hex"
	"fmt"
	"github.com/herrfz/cellemu/ecdh"
	msg "github.com/herrfz/gowdc/messages"
)

func EmulCoordNode(dl_chan, ul_chan chan []byte) {
	for {
		buf := <-dl_chan

		switch buf[1] {
		case 0x01:
			fmt.Println("received CoordNode connect")
			fake := []byte{0xde, 0xad, 0xbe, 0xef,
				0xde, 0xad, 0xbe, 0xef}
			copy(msg.WDC_CONNECTION_RES[2:], fake)
			ul_chan <- msg.WDC_CONNECTION_RES
			fmt.Println("CoordNode connection created")

		case 0x03:
			fmt.Println("received CoordNode disconnect")
			ul_chan <- msg.WDC_DISCONNECTION_REQ_ACK
			fmt.Println("CoordNode disconnected")

		case 0x07:
			fmt.Println("received set CorrdNode long address")
			ul_chan <- msg.WDC_SET_COOR_LONG_ADDR_REQ_ACK
			fmt.Println("CorrdNode long address set")

		case 0x10:
			fmt.Println("received WDC sync")
			fmt.Println("WDC sync-ed")

		case 0x11: // start TDMA
			fmt.Println("received start TDMA:",
				hex.EncodeToString(buf))
			msg.WDC_GET_TDMA_RES[2] = 0x01 // running
			copy(msg.WDC_GET_TDMA_RES[3:], buf[2:])
			msg.WDC_ACK[1] = 0x12 // START_TDMA_REQ_ACK
			ul_chan <- msg.WDC_ACK
			fmt.Println("TDMA started")

		case 0x13: // stop TDMA
			fmt.Println("received stop TDMA")
			msg.WDC_ACK[1] = 0x14 // STOP_TDMA_REQ_ACK
			ul_chan <- msg.WDC_ACK
			fmt.Println("TDMA stopped")

		case 0x15: // TDMA status
			fmt.Println("received TDMA status request")
			ul_chan <- msg.WDC_GET_TDMA_RES
			fmt.Println("sent TDMA status response:",
				hex.EncodeToString(msg.WDC_GET_TDMA_RES))

		case 0x17: // data request
			fmt.Println("received data request",
				hex.EncodeToString(buf))
			// parse WDC_MAC_DATA_REQ, cf. EADS MAC Table 29
			HANDLE := buf[2]
			TXOPTS := buf[3]
			ADDRMODE := (TXOPTS>>3)&1
			DSTPAN := buf[4:6]
			if ADDRMODE == 0 {
				DSTADDR := buf[6:8]
				MSDULEN := buf[8]
				MSDU := buf[9:]
			} else if ADDRMODE == 1 {
				DSTADDR := buf[6:14]
				MSDULEN := buf[14]
				MSDU := buf[15:]
			}
			if MSDULEN != len(MSDU) {
				// TODO, currently drop
				continue
			}

			// first, send confirmation
			msg.WDC_MAC_DATA_CON[2] = HANDLE
			msg.WDC_MAC_DATA_CON[3] = 0x00
			ul_chan <- msg.WDC_MAC_DATA_CON
			fmt.Println("sent data confirmation",
				hex.EncodeToString(msg.WDC_MAC_DATA_CON))

			mID := MSDU[0]
			// TODO key exchange emulation will be done here
			switch mID {
			case 0x09, 0x0A:
				//dosmth
			case 0x01:
				//donik / unauth ecdh
				dap := MSDU[1:]
				if !ecdh.CheckPublic(dap) {
					// drop
					continue
				}
				db, _ := ecdh.GeneratePrivate()
				dbp := ecdh.GeneratePublic(db)
				zz, _ := ecdh.GenerateSecret(db, dap)
				// TODO compute NIK := sha256(zz)[:128]

				// FCF (Table 4): 0010000000100110
				fmt.Println(zz, dbp)
				
			case 0x03, 0x05:
				//doltss, dosessionkey / auth ecdh
			case 0x0B:
				//dosbk
			default:
				fmt.Println("received wrong mID")
				// drop
				continue
			}

		default:
			fmt.Println("received wrong cmd")
			// send back WDC_ERROR
			msg.WDC_ERROR[2] = byte(msg.WRONG_CMD)
			// TODO confirm this (send over d, not c channel)
			ul_chan <- msg.WDC_ERROR
		}
	}
}
