// This package implements workers for external components
package worker

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/herrfz/coordnode/crypto/blockcipher"
	"github.com/herrfz/coordnode/crypto/ecdh"
	"github.com/herrfz/coordnode/crypto/hmac"
	"time"
)

func DoDataRequest(dl_chan, ul_chan chan []byte) {
	var NIK, S, AK, SIK, SCK []byte
	var UL_POLICY byte
	var COUNTER_BYTE = make([]byte, 4)
	var COUNTER uint32 = 0
	// trailing LQI, ED, RX status, RX slot; TODO, all zeros for now
	// I have to add one 0x00 to remove server error!! why!! <-- maybe already solved..
	var trail = []byte{0x00, 0x00, 0x00, 0x00, 0x00}

	for {
		buf, more := <-dl_chan
		if !more {
			fmt.Println("stopping CoordNode emulator...")
			close(ul_chan)
			break // stop goroutine no more data
		}

		wdc_req := WDC_REQ{}
		wdc_req.ParseWDCReq(buf)
		if wdc_req.MSDULEN != len(wdc_req.MSDU) {
			fmt.Println("MSDU length mismatch, on frame:", wdc_req.MSDULEN, ", received:", len(wdc_req.MSDU))
			continue
		}

		go func() {
			mID := wdc_req.MSDU[0]
			switch mID {
			// application data
			case 0x09, 0x0A:
				fmt.Println("received application data:", hex.EncodeToString(wdc_req.MSDU))

				sensor_addr := append(wdc_req.DSTPAN, wdc_req.DSTADDR...)
				wdc_addr := []byte{0xff, 0xff, // WDC PAN
					0xff, 0xff} // WDC address

				// test uplink
				COUNTER++
				binary.LittleEndian.PutUint32(COUNTER_BYTE, COUNTER)
				MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				MHR = append(MHR, append(wdc_addr, sensor_addr...)...)
				MSDU_HEADER := append([]byte{0x09}, COUNTER_BYTE...)
				MSDU_PAYLOAD := []byte{0xca, 0xfe}

				var procMSDU []byte
				if UL_POLICY == 0x01 {
					procMSDU, _ = blockcipher.AESEncryptCBCPKCS7(SCK, MSDU_PAYLOAD)
				} else {
					procMSDU = MSDU_PAYLOAD
				}

				MPDU := append(MHR, append(MSDU_HEADER, procMSDU...)...)

				msgMAC := hmac.SHA256HMACGenerate(SIK, MPDU)
				MFR := []byte{0xde, 0xad} // FCS, 16-bit CRC <--fake
				PSDU := append(MPDU, append(msgMAC, MFR...)...)
				IND := MakeWDCInd(PSDU, trail)

				time.Sleep(1 * time.Second)
				ul_chan <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

			// generate NIK / unauth ecdh
			case 0x01:
				dap := wdc_req.MSDU[1:]
				if !ecdh.CheckPublic(dap) {
					// drop
					fmt.Println("received invalid public key:", hex.EncodeToString(dap))
					return
				}
				db, _ := ecdh.GeneratePrivate()
				dbp := ecdh.GeneratePublic(db)
				zz, _ := ecdh.GenerateSecret(db, dap)
				fmt.Println("shared secret:", hex.EncodeToString(zz))

				zz_h := sha256.Sum256(zz)
				NIK = zz_h[:16] // NIK := first 128 bits / 16 Bytes of the hash of the secret
				fmt.Println("For sensor address:", hex.EncodeToString(wdc_req.DSTADDR),
					"generated NIK:", hex.EncodeToString(NIK))

				// the MPDU of the return message
				MPDU := MakeMPDU([]byte{0xff, 0xff}, []byte{0xff, 0xff}, wdc_req.DSTPAN, wdc_req.DSTADDR,
					append([]byte{0x02}, // mID NIK response
						dbp...))

				IND := MakeWDCInd(MPDU, trail)

				ul_chan <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

			// generate LTSS or generate session keys / auth ecdh
			case 0x03, 0x05:
				authkey := make([]byte, 16)
				if mID == 0x03 {
					copy(authkey, NIK)
				} else {
					copy(authkey, AK)
				}
				// ltss, sessionkey / auth ecdh
				msgMAC := wdc_req.MSDU[wdc_req.MSDULEN-8:] // msgMAC := last 8 Bytes of MSDU
				MSDU_NOMAC := make([]byte, wdc_req.MSDULEN-8)
				copy(MSDU_NOMAC, wdc_req.MSDU[:wdc_req.MSDULEN-8]) // if I don't do this the MSDU gets corrupted!?!?!?

				// construct MPDU for which the msgMAC is computed
				MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				sensor_addr := append(wdc_req.DSTPAN, wdc_req.DSTADDR...)
				wdc_addr := []byte{0xff, 0xff, // WDC PAN
					0xff, 0xff} // WDC address
				MHR = append(MHR, append(sensor_addr, wdc_addr...)...)
				MPDU := append(MHR, MSDU_NOMAC...)

				if expectedMAC, match := hmac.SHA256HMACVerify(authkey, MPDU, msgMAC); !match {
					// MAC verification fails, drop
					fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(MPDU),
						"expected:", hex.EncodeToString(expectedMAC))
					return
				}

				dap := MSDU_NOMAC[1:]
				if !ecdh.CheckPublic(dap) {
					// drop
					fmt.Println("received invalid public key:", hex.EncodeToString(dap))
					return
				}
				db, _ := ecdh.GeneratePrivate()
				dbp := ecdh.GeneratePublic(db)
				zz, _ := ecdh.GenerateSecret(db, dap)

				// generate keys from SHA256
				KEYS := sha256.Sum256(zz)

				// construct return MPDU
				MHR = []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				MHR = append(MHR, append(wdc_addr, sensor_addr...)...)

				if mID == 0x03 {
					MPDU = append(MHR, append([]byte{0x04}, // mID LTSS response
						dbp...)...)
					S = KEYS[:16]
					AK = KEYS[16:]
					fmt.Println("For sensor address:", hex.EncodeToString(wdc_req.DSTADDR),
						"created LTSS:", hex.EncodeToString(S), hex.EncodeToString(AK))
				} else {
					MPDU = append(MHR, append([]byte{0x06}, // mID session key response
						dbp...)...)
					SIK = KEYS[:16]
					SCK = KEYS[16:]
					fmt.Println("For sensor address:", hex.EncodeToString(wdc_req.DSTADDR),
						"created session keys:", hex.EncodeToString(SIK), hex.EncodeToString(SCK))
				}

				msgMAC = hmac.SHA256HMACGenerate(authkey, MPDU)
				MFR := []byte{0xde, 0xad} // FCS, 16-bit CRC <--fake
				PSDU := append(MPDU, append(msgMAC, MFR...)...)
				IND := MakeWDCInd(PSDU, trail)

				ul_chan <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

			// update SBK
			case 0x07:
				msgMAC := wdc_req.MSDU[wdc_req.MSDULEN-8:] // msgMAC := last 8 Bytes of MSDU
				MSDU_NOMAC := make([]byte, wdc_req.MSDULEN-8)
				copy(MSDU_NOMAC, wdc_req.MSDU[:wdc_req.MSDULEN-8]) // if I don't do this the MSDU gets corrupted!?!?!?

				// construct MPDU for which the msgMAC is computed
				MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				sensor_addr := append(wdc_req.DSTPAN, wdc_req.DSTADDR...)
				wdc_addr := []byte{0xff, 0xff, // WDC PAN
					0xff, 0xff} // WDC address
				MHR = append(MHR, append(sensor_addr, wdc_addr...)...)
				MPDU := append(MHR, MSDU_NOMAC...)

				if expectedMAC, match := hmac.SHA256HMACVerify(SIK, MPDU, msgMAC); !match {
					// MAC verification fails, drop
					fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(MPDU),
						"expected:", hex.EncodeToString(expectedMAC))
					return
				}

				sbk, err := blockcipher.AESDecryptCBCPKCS7(SCK, MSDU_NOMAC[1:])
				if err != nil {
					fmt.Println("error decrypting SBK:", err.Error())
					return
				}
				fmt.Println("For sensor address:", hex.EncodeToString(wdc_req.DSTADDR),
					"got SBK:", hex.EncodeToString(sbk))

				// construct return MPDU
				MHR = []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				MHR = append(MHR, append(wdc_addr, sensor_addr...)...)
				MPDU = append(MHR, append([]byte{0x08}, // mID SBK update response
					byte(0x00))...) // status 0x00: OK
				msgMAC = hmac.SHA256HMACGenerate(SIK, MPDU)
				MFR := []byte{0xde, 0xad} // FCS, 16-bit CRC <--fake
				PSDU := append(MPDU, append(msgMAC, MFR...)...)
				IND := MakeWDCInd(PSDU, trail)

				time.Sleep(1 * time.Second)
				ul_chan <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

			// update sensor nodes security policy
			case 0x0B:
				msgMAC := wdc_req.MSDU[wdc_req.MSDULEN-8:] // msgMAC := last 8 Bytes of MSDU
				MSDU_NOMAC := make([]byte, wdc_req.MSDULEN-8)
				copy(MSDU_NOMAC, wdc_req.MSDU[:wdc_req.MSDULEN-8]) // if I don't do this the MSDU gets corrupted!?!?!?

				// construct MPDU for which the msgMAC is computed
				MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				sensor_addr := append(wdc_req.DSTPAN, wdc_req.DSTADDR...)
				wdc_addr := []byte{0xff, 0xff, // WDC PAN
					0xff, 0xff} // WDC address
				MHR = append(MHR, append(sensor_addr, wdc_addr...)...)
				MPDU := append(MHR, MSDU_NOMAC...)

				if expectedMAC, match := hmac.SHA256HMACVerify(SIK, MPDU, msgMAC); !match {
					// MAC verification fails, drop
					fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(MPDU),
						"expected:", hex.EncodeToString(expectedMAC))
					return
				}

				fmt.Println("For sensor address:", hex.EncodeToString(wdc_req.DSTADDR),
					"got policy:", hex.EncodeToString(MSDU_NOMAC[1:]))
				// DL_POLICY = MSDU_NOMAC[1]
				UL_POLICY = MSDU_NOMAC[2]

				// construct return MPDU
				MHR = []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
					0x00} // sequence number, must be set to zero
				MHR = append(MHR, append(wdc_addr, sensor_addr...)...)
				MPDU = append(MHR, append([]byte{0x0C}, // mID policy update response
					byte(0x00))...) // status 0x00: OK
				msgMAC = hmac.SHA256HMACGenerate(SIK, MPDU)
				MFR := []byte{0xde, 0xad} // FCS, 16-bit CRC <--fake
				PSDU := append(MPDU, append(msgMAC, MFR...)...)
				IND := MakeWDCInd(PSDU, trail)

				time.Sleep(1 * time.Second)
				ul_chan <- IND
				fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

			default:
				fmt.Println("received wrong mID")
				// drop
				return
			}
		}()
	}
	fmt.Println("CoordNode emulator stopped")
}
