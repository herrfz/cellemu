// This package implements workers for external components
package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/herrfz/cellemu/crypto/ecdh"
	msg "github.com/herrfz/gowdc/messages"
)

func EmulCoordNode(dl_chan, ul_chan, ul_chan_2 chan []byte) {
	for {
		var MSDULEN int
		var MSDU []byte //, DSTADDR []byte

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
			ADDRMODE := (TXOPTS >> 3) & 1 // TBC, bit 4 of TXOPTS
			//DSTPAN := buf[4:6]
			if ADDRMODE == 0 { // short addr mode
				//DSTADDR = buf[6:8]  // (16 bits)
				MSDULEN = int(buf[8])
				MSDU = buf[9:]
			} else if ADDRMODE == 1 { // long addr mode
				//DSTADDR = buf[6:14]  // (64 bits)
				MSDULEN = int(buf[14])
				MSDU = buf[15:]
			}
			if MSDULEN != len(MSDU) {
				// TODO, currently drop
				continue
			}

			// first, send confirmation
			msg.WDC_MAC_DATA_CON[2] = HANDLE
			msg.WDC_MAC_DATA_CON[3] = 0x00 // success
			ul_chan <- msg.WDC_MAC_DATA_CON
			fmt.Println("sent data confirmation",
				hex.EncodeToString(msg.WDC_MAC_DATA_CON))

			// prepare a return IND message
			// DOESN'T WORK, ARRAY OUT OF BOUND EXCEPTION AT SERVER
			// FCF: 0010 0000 0010 0000
			MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
				0x00,       // sequence number, must be set to zero
				0xff, 0xff, // WDC PAN
				0xff, 0xff, // WDC address
				0x1c, 0xaa, // sensor PAN, little endian, TODO use DSTPAN
				0x01, 0x00} // sensor address, little endian, TODO use DSTADDR

			// trailing LQI, ED, RX status, RX slot; TODO, all zeros for now
			// I have to add one 0x00 to remove server error!! why!!
			trail := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

			mID := MSDU[0]
			switch mID {
			case 0x09, 0x0A:
				// do nothing
				continue
			case 0x01:
				// nik / unauth ecdh
				dap := MSDU[1:]
				if !ecdh.CheckPublic(dap) {
					// drop
					fmt.Println("received invalid public key:",
						hex.EncodeToString(dap))
					continue
				}
				db, _ := ecdh.GeneratePrivate()
				dbp := ecdh.GeneratePublic(db)
				zz, _ := ecdh.GenerateSecret(db, dap)
				zz_h := sha256.Sum256(zz)
				NIK := zz_h[:16] // NIK := first 128 bit of the hash of the secret
				fmt.Println("generated NIK:",
					hex.EncodeToString(NIK))

				MFR := []byte{0xde, 0xad}                // FCS, 16-bit CRC <--fake
				PSDU := append(MHR, append([]byte{0x02}, // mID NIK response
					append(dbp, MFR...)...)...)
				PHR := []byte{byte(len(PSDU))}

				IND := append(PHR, append(PSDU, trail...)...)
				IND = append([]byte{byte(len(IND))}, append([]byte{0x19}, // WDC_MAC_DATA_IND
					IND...)...)
				fmt.Println("created data IND:",
					hex.EncodeToString(IND))

				ul_chan_2 <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:",
					hex.EncodeToString(IND))

			case 0x03, 0x05:
				// ltss, sessionkey / auth ecdh
			case 0x0B:
				// sbk
			default:
				fmt.Println("received wrong mID")
				// drop
				continue
			}

		default:
			fmt.Println("received wrong cmd")
			// send back WDC_ERROR
			msg.WDC_ERROR[2] = byte(msg.WRONG_CMD)
			ul_chan <- msg.WDC_ERROR
		}
	}
}
