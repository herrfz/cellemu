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
	"sync"
	"time"
)

func DoDataRequest(dl_chan, ul_chan, app_dl_chan, app_ul_chan chan []byte) {
	var NIK, S, AK, SIK, SCK []byte
	var UL_POLICY byte
	var COUNTER_BYTE = make([]byte, 4)
	var COUNTER uint32 = 0
	// trailing LQI, ED, RX status, RX slot; TODO, all zeros for now
	var trail = []byte{0x00, 0x00, 0x00, 0x00, 0x00}

	// protect access to uplink channel (apps and keymgmt goroutines)
	var mutex = &sync.Mutex{}

LOOP:
	for {
		select {
		case payload, more := <-app_ul_chan:
			if !more {
				continue // give a chance to close dl_chan
			}
			// uplink
			COUNTER++
			binary.BigEndian.PutUint32(COUNTER_BYTE, COUNTER)

			var procMSDU []byte
			if UL_POLICY == 0x01 {
				procMSDU, _ = blockcipher.AESEncryptCBCPKCS7(SCK, payload)
			} else {
				procMSDU = payload
			}

			ul_frame := UL_AUTH_FRAME{}
			ul_frame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
				[]byte{0xb1, 0xca}, []byte{0x00, 0x00}, // sensor; TODO: configurable
				[]byte{0x09}, // mID unicast
				append(COUNTER_BYTE, procMSDU...), SIK)
			IND := MakeWDCInd(ul_frame.FRAME, trail)

			mutex.Lock()
			ul_chan <- IND
			mutex.Unlock()
			fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

		case buf, more := <-dl_chan:
			if !more {
				fmt.Println("stopping CoordNode emulator...")
				close(ul_chan)
				break LOOP // stop goroutine no more data
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
					// authenticate, check replay, decrypt
					// then:
					fmt.Println("received application data:", hex.EncodeToString(wdc_req.MSDU))

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

					mutex.Lock()
					ul_chan <- IND
					mutex.Unlock()
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
					dl_frame := DL_AUTH_FRAME{}
					dl_frame.MakeDownlinkFrame(wdc_req)

					if expectedMAC, match := hmac.SHA256HMACVerify(authkey, dl_frame.AUTHDATA, dl_frame.MAC); !match {
						// MAC verification fails, drop
						fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(dl_frame.AUTHDATA),
							"expected:", hex.EncodeToString(expectedMAC))
						return
					}

					dap := dl_frame.PAYLOAD
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
					ul_frame := UL_AUTH_FRAME{}
					ul_mid := []byte{}

					if mID == 0x03 {
						ul_mid = []byte{0x04}
						S = KEYS[:16]
						AK = KEYS[16:]
						fmt.Println("For sensor address:", hex.EncodeToString(dl_frame.DSTADDR),
							"created LTSS:", hex.EncodeToString(S), hex.EncodeToString(AK))
					} else {
						ul_mid = []byte{0x06}
						SIK = KEYS[:16]
						SCK = KEYS[16:]
						COUNTER = 0
						fmt.Println("For sensor address:", hex.EncodeToString(dl_frame.DSTADDR),
							"created session keys:", hex.EncodeToString(SIK), hex.EncodeToString(SCK))
					}

					ul_frame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
						dl_frame.DSTPAN, dl_frame.DSTADDR, ul_mid, dbp, authkey)
					IND := MakeWDCInd(ul_frame.FRAME, trail)
					mutex.Lock()
					ul_chan <- IND
					mutex.Unlock()
					fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

				// update SBK
				case 0x07:
					dl_frame := DL_AUTH_FRAME{}
					dl_frame.MakeDownlinkFrame(wdc_req)

					if expectedMAC, match := hmac.SHA256HMACVerify(SIK, dl_frame.AUTHDATA, dl_frame.MAC); !match {
						// MAC verification fails, drop
						fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(dl_frame.AUTHDATA),
							"expected:", hex.EncodeToString(expectedMAC))
						return
					}

					sbk, err := blockcipher.AESDecryptCBCPKCS7(SCK, dl_frame.PAYLOAD)
					if err != nil {
						fmt.Println("error decrypting SBK:", err.Error())
						return
					}
					fmt.Println("For sensor address:", hex.EncodeToString(dl_frame.DSTADDR),
						"got SBK:", hex.EncodeToString(sbk))

					// construct return MPDU
					ul_frame := UL_AUTH_FRAME{}
					ul_frame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
						dl_frame.DSTPAN, dl_frame.DSTADDR, []byte{0x08}, // mID SBK update response
						[]byte{0x00}, // status OK
						SIK)
					IND := MakeWDCInd(ul_frame.FRAME, trail)

					time.Sleep(1 * time.Second)
					mutex.Lock()
					ul_chan <- IND
					mutex.Unlock()
					fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

				// update sensor nodes security policy
				case 0x0B:
					dl_frame := DL_AUTH_FRAME{}
					dl_frame.MakeDownlinkFrame(wdc_req)

					if expectedMAC, match := hmac.SHA256HMACVerify(SIK, dl_frame.AUTHDATA, dl_frame.MAC); !match {
						// MAC verification fails, drop
						fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(dl_frame.AUTHDATA),
							"expected:", hex.EncodeToString(expectedMAC))
						return
					}

					fmt.Println("For sensor address:", hex.EncodeToString(dl_frame.DSTADDR),
						"got policy:", hex.EncodeToString(dl_frame.PAYLOAD))
					// DL_POLICY = dl_frame.PAYLOAD[0]
					UL_POLICY = dl_frame.PAYLOAD[1]

					// construct return MPDU
					ul_frame := UL_AUTH_FRAME{}
					ul_frame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
						dl_frame.DSTPAN, dl_frame.DSTADDR, []byte{0x0C}, // mID policy update response
						[]byte{0x00}, // status OK
						SIK)
					IND := MakeWDCInd(ul_frame.FRAME, trail)

					time.Sleep(1 * time.Second)
					mutex.Lock()
					ul_chan <- IND
					mutex.Unlock()
					fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

				default:
					fmt.Println("received wrong mID")
					// drop
					return
				}
			}()

		}
	}
	fmt.Println("CoordNode emulator stopped")
}
