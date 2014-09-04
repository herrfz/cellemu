// This package implements workers for external components
package worker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/herrfz/coordnode/crypto/blockcipher"
	"github.com/herrfz/coordnode/crypto/ecdh"
	msg "github.com/herrfz/gowdc/messages"
	"time"
)

func receive_with_timeout (channel chan []byte, timeout time.Duration) ([]byte, error) {
	select {
	case buf := <-channel:
		return buf, nil
	case <-time.After(timeout * time.Second):
		return []byte{}, fmt.Errorf("timeout while receiving message")
	}
}

func EmulCoordNode(dl_chan, ul_chan chan []byte, serial bool, device string) {
	var MSDULEN int
	var MSDU []byte

	var NIK, S, AK, SIK, SCK []byte
	var DSTADDR []byte

	var TIMEOUT time.Duration
	TIMEOUT = 10

	serial_dl_chan := make(chan []byte)
	serial_ul_chan := make(chan []byte)
	if serial {
		go DoSerial(serial_dl_chan, serial_ul_chan, device)
	}

	for {
		buf, more := <-dl_chan

		if !more {
			fmt.Println("stopping CoordNode emulator...")
			if serial {
				close(serial_dl_chan)
				<-serial_ul_chan
			}
			ul_chan <- []byte{0xff, 0xff}
			break // stop goroutine no more data
		}

		if len(buf) == 0 {
			dummy := make([]byte, 0)
			ul_chan <- dummy
			continue
		}

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

		case 0x09:
			fmt.Println("received reset command")
			ul_chan <- msg.WDC_RESET_REQ_ACK
			fmt.Println("CoordNode reset")

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
			msg.WDC_GET_TDMA_RES[2] = 0x00 // stopped
			msg.WDC_ACK[1] = 0x14          // STOP_TDMA_REQ_ACK
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
			DSTPAN := buf[4:6]
			if ADDRMODE == 0 { // short addr mode
				DSTADDR = buf[6:8] // (16 bits)
				MSDULEN = int(buf[8])
				MSDU = buf[9:]
			} else if ADDRMODE == 1 { // long addr mode
				DSTADDR = buf[6:14] // (64 bits)
				MSDULEN = int(buf[14])
				MSDU = buf[15:]
			}
			if MSDULEN != len(MSDU) {
				fmt.Println("MSDU length mismatch, on frame:", MSDULEN, ", received:", len(MSDU))
				continue
			}

			// first, send confirmation
			msg.WDC_MAC_DATA_CON[2] = HANDLE
			msg.WDC_MAC_DATA_CON[3] = 0x00 // success
			ul_chan <- msg.WDC_MAC_DATA_CON
			fmt.Println("sent data confirmation",
				hex.EncodeToString(msg.WDC_MAC_DATA_CON))

			// trailing LQI, ED, RX status, RX slot; TODO, all zeros for now
			// I have to add one 0x00 to remove server error!! why!!
			trail := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

			mID := MSDU[0]
			switch mID {
			// application data
			case 0x09, 0x0A:
				// do nothing
				continue

			// generate NIK
			case 0x01:
				if serial {
					MPDU := MakeRequest(DSTPAN, DSTADDR, []byte{0xff, 0xff}, []byte{0xff, 0xff}, MSDU)
					serial_dl_chan <- MPDU
					PSDU, err := receive_with_timeout(serial_ul_chan, TIMEOUT)
					if err != nil {
						fmt.Println("error reading from serial:", err.Error())
						continue
					}
					IND := MakeWDCInd(PSDU, trail)
					ul_chan <- IND
					continue
				}

				// nik / unauth ecdh
				dap := MSDU[1:]
				if !ecdh.CheckPublic(dap) {
					// drop
					fmt.Println("received invalid public key:", hex.EncodeToString(dap))
					continue
				}
				db, _ := ecdh.GeneratePrivate()
				dbp := ecdh.GeneratePublic(db)
				zz, _ := ecdh.GenerateSecret(db, dap)
				fmt.Println("shared secret:", hex.EncodeToString(zz))
				zz_h := sha256.Sum256(zz)
				NIK = zz_h[:16] // NIK := first 128 bits / 16 Bytes of the hash of the secret
				fmt.Println("For sensor address:", hex.EncodeToString(DSTADDR),
					"generated NIK:", hex.EncodeToString(NIK))

				// construct WDC_MAC_DATA_IND return message
				MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00,       // sequence number, must be set to zero
					0xff, 0xff, // WDC PAN
					0xff, 0xff} // WDC address
				MHR = append(MHR, append(DSTPAN, DSTADDR...)...)

				MFR := []byte{0xde, 0xad} // FCS, 16-bit CRC <--fake

				PSDU := append(MHR, append([]byte{0x02}, // mID NIK response
					append(dbp, MFR...)...)...)

				IND := MakeWDCInd(PSDU, trail)

				ul_chan <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

			// generate LTSS or generate session keys
			case 0x03, 0x05:
				if serial {
					MPDU := MakeRequest(DSTPAN, DSTADDR, []byte{0xff, 0xff}, []byte{0xff, 0xff}, MSDU)
					serial_dl_chan <- MPDU
					PSDU, err := receive_with_timeout(serial_ul_chan, TIMEOUT)
					if err != nil {
						fmt.Println("error reading from serial:", err.Error())
						continue
					}
					IND := MakeWDCInd(PSDU, trail)
					ul_chan <- IND
					continue
				}

				authkey := make([]byte, 16)
				if mID == 0x03 {
					copy(authkey, NIK)
				} else {
					copy(authkey, AK)
				}
				// ltss, sessionkey / auth ecdh
				msgMAC := MSDU[MSDULEN-8:] // msgMAC := last 8 Bytes of MSDU
				MSDU_NOMAC := make([]byte, MSDULEN-8)
				copy(MSDU_NOMAC, MSDU[:MSDULEN-8])

				// construct WDC_MAC_DATA_REQ for which the msgMAC is computed
				MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				sensor_addr := append(DSTPAN, DSTADDR...)
				wdc_addr := []byte{0xff, 0xff, // WDC PAN
					0xff, 0xff} // WDC address

				MHR = append(MHR, append(sensor_addr, wdc_addr...)...)

				MPDU := append(MHR, MSDU_NOMAC...)

				mac := hmac.New(sha256.New, authkey)
				mac.Write(MPDU)
				sha256_mac := mac.Sum(nil)
				expectedMAC := make([]byte, 8)
				copy(expectedMAC, sha256_mac[:8]) // truncate to first 8 Bytes
				if !hmac.Equal(msgMAC, expectedMAC) {
					// MAC verification fails, drop
					fmt.Printf("failed MAC verification, MPDU: %s, key: %s, expectedMAC: %s\n",
						hex.EncodeToString(MPDU), hex.EncodeToString(authkey), hex.EncodeToString(expectedMAC))
					continue
				}

				dap := MSDU_NOMAC[1:]
				if !ecdh.CheckPublic(dap) {
					// drop
					fmt.Println("received invalid public key:",
						hex.EncodeToString(dap))
					continue
				}
				db, _ := ecdh.GeneratePrivate()
				dbp := ecdh.GeneratePublic(db)
				zz, _ := ecdh.GenerateSecret(db, dap)

				// generate keys from SHA256
				KEYS := sha256.Sum256(zz)

				// construct WDC_MAC_DATA_IND return message
				MHR = []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				MHR = append(MHR, append(wdc_addr, sensor_addr...)...)

				if mID == 0x03 {
					MPDU = append(MHR, append([]byte{0x04}, // mID LTSS response
						dbp...)...)
					S = KEYS[:16]
					AK = KEYS[16:]
					fmt.Println("For sensor address:", hex.EncodeToString(DSTADDR),
						"created LTSS:", hex.EncodeToString(S), hex.EncodeToString(AK))
				} else {
					MPDU = append(MHR, append([]byte{0x06}, // mID session key response
						dbp...)...)
					SIK = KEYS[:16]
					SCK = KEYS[16:]
					fmt.Println("For sensor address:", hex.EncodeToString(DSTADDR),
						"created session keys:", hex.EncodeToString(SIK), hex.EncodeToString(SCK))
				}

				mac = hmac.New(sha256.New, authkey)
				mac.Write(MPDU)
				sha256_mac = mac.Sum(nil)
				copy(msgMAC, sha256_mac[:8]) // truncate to first 8 Bytes

				MFR := []byte{0xde, 0xad} // FCS, 16-bit CRC <--fake

				PSDU := append(MPDU, append(msgMAC, MFR...)...)

				IND := MakeWDCInd(PSDU, trail)

				ul_chan <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

			// update SBK
			case 0x07:
				if serial {
					MPDU := MakeRequest(DSTPAN, DSTADDR, []byte{0xff, 0xff}, []byte{0xff, 0xff}, MSDU)
					serial_dl_chan <- MPDU
					PSDU, err := receive_with_timeout(serial_ul_chan, TIMEOUT)
					if err != nil {
						fmt.Println("error reading from serial:", err.Error())
						continue
					}
					IND := MakeWDCInd(PSDU, trail)
					ul_chan <- IND
					continue
				}

				msgMAC := MSDU[MSDULEN-8:] // msgMAC := last 8 Bytes of MSDU
				MSDU_NOMAC := make([]byte, MSDULEN-8)
				copy(MSDU_NOMAC, MSDU[:MSDULEN-8])

				// construct WDC_MAC_DATA_REQ for which the msgMAC is computed
				MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				sensor_addr := append(DSTPAN, DSTADDR...)
				wdc_addr := []byte{0xff, 0xff, // WDC PAN
					0xff, 0xff} // WDC address

				MHR = append(MHR, append(sensor_addr, wdc_addr...)...)

				MPDU := append(MHR, MSDU_NOMAC...)

				mac := hmac.New(sha256.New, SIK)
				mac.Write(MPDU)
				sha256_mac := mac.Sum(nil)
				expectedMAC := make([]byte, 8)
				copy(expectedMAC, sha256_mac[:8]) // truncate to first 8 Bytes
				if !hmac.Equal(msgMAC, expectedMAC) {
					// MAC verification fails, drop
					fmt.Printf("failed MAC verification, MPDU: %s, key: %s, expectedMAC: %s\n",
						hex.EncodeToString(MPDU), hex.EncodeToString(SIK), hex.EncodeToString(expectedMAC))
					continue
				}

				sbk, err := blockcipher.AESDecryptCBCPKCS7(SCK, MSDU_NOMAC[1:])
				if err != nil {
					fmt.Println("error decrypting SBK:", err.Error())
					continue
				}
				fmt.Println("For sensor address:", hex.EncodeToString(DSTADDR),
					"got SBK:", hex.EncodeToString(sbk))

				// construct WDC_MAC_DATA_IND return message
				MHR = []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				MHR = append(MHR, append(wdc_addr, sensor_addr...)...)
				MPDU = append(MHR, append([]byte{0x08}, // mID SBK update response
					byte(0x00))...) // status 0x00: OK

				mac = hmac.New(sha256.New, SIK)
				mac.Write(MPDU)
				sha256_mac = mac.Sum(nil)
				copy(msgMAC, sha256_mac[:8]) // truncate to first 8 Bytes

				MFR := []byte{0xde, 0xad} // FCS, 16-bit CRC <--fake

				PSDU := append(MPDU, append(msgMAC, MFR...)...)

				IND := MakeWDCInd(PSDU, trail)

				ul_chan <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

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

	fmt.Println("CoordNode emulator stopped")
}
