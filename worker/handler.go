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

func DoDataRequest(nodeAddr []byte, dlCh, ulCh, appDlCh, appUlCh, crossCh chan []byte, secure bool) {
	var NIK, S, AK, SIK, SCK []byte
	var UL_POLICY byte
	var COUNTER_BYTE = make([]byte, 4)
	var COUNTER uint32 = 0
	var nfcData = make([]byte, 6)
	// trailing LQI, ED, RX status, RX slot; TODO, all zeros for now
	var trail = []byte{0x00, 0x00, 0x96, 0x00, 0x00}

	// protect access to uplink channel (apps and keymgmt goroutines)
	var mutex = &sync.Mutex{}

LOOP:
	for {
		select {
		case appData := <-crossCh: // allow application to send misc data
			copy(nfcData, appData) // do nothing, just store

		case payload := <-appUlCh:
			// uplink
			ulFrame := UL_FRAME{auth: secure}
			if secure {
				COUNTER++
				binary.BigEndian.PutUint32(COUNTER_BYTE, COUNTER)

				var procMSDU []byte
				if UL_POLICY == 0x01 {
					procMSDU, _ = blockcipher.AESEncryptCBCPKCS7(SCK, payload)
				} else {
					procMSDU = payload
				}

				ulFrame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
					[]byte{0xb1, 0xca}, // sensor pan
					nodeAddr,           // sensor addr
					[]byte{0x09},       // mID unicast
					append(COUNTER_BYTE, procMSDU...), SIK)

			} else {
				ulFrame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
					[]byte{0xb1, 0xca}, // sensor pan
					nodeAddr,           // sensor addr
					[]byte{0x09},       // mID unicast
					payload, SIK)       // SIK is not actually used here
			}

			IND := MakeWDCInd(ulFrame.FRAME, trail)

			mutex.Lock()
			ulCh <- IND
			mutex.Unlock()
			fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

		case buf, more := <-dlCh:
			if !more {
				close(appDlCh)
				<-appUlCh
				close(ulCh)
				break LOOP // stop goroutine no more data
			}

			wdcReq := WDC_REQ{}
			wdcReq.ParseWDCReq(buf)

			if len(wdcReq.MSDU) == 0 {
				fmt.Println("zero length MSDU")
				continue
			}

			if wdcReq.MSDULEN != len(wdcReq.MSDU) {
				fmt.Println("MSDU length mismatch, on frame:", wdcReq.MSDULEN, ", received:", len(wdcReq.MSDU))
				continue
			}

			go func() {
				if wdcReq.MACCMD {
					cmdID := wdcReq.MSDU[0]
					switch cmdID {
					case 0x00: // beacon
					case 0x01: // set param
					case 0x02: // get param
					case 0x04: // disassociation req
						reassocAllowed := (wdcReq.MSDU[1] == 0xfe) // 0xFE for allowed association TBC
						if reassocAllowed {
							fmt.Println("received disassociation request, reassociate allowed")
							time.Sleep(1000 * time.Millisecond)
							assocReq := append(append([]byte{0x05, 0x01}, // assocReq cmd id, seqnbr
								nfcData...),
								0x01) // sensorType

							MPDU := MakeMPDU([]byte{0x04, 0xd8},
								[]byte{0xff, 0xff}, []byte{0xff, 0xff},
								[]byte{0xb1, 0xca}, append(nodeAddr, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...),
								assocReq)

							IND := MakeWDCInd(MPDU, trail)

							mutex.Lock()
							ulCh <- IND
							mutex.Unlock()
							fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

						} else {
							fmt.Println("received disassociation request, reassociate not allowed")
						}
					case 0x06: // assoc resp
						fmt.Println("received association response")
					case 0x07: // reset req
					default:
						fmt.Println("received wrong MAC command ID")
						return
					}
				} else {
					mID := wdcReq.MSDU[0]
					switch mID {
					// application data
					case 0x09, 0x0A:
						// authenticate, check replay, decrypt
						// then:
						fmt.Println("received application data:", hex.EncodeToString(wdcReq.MSDU))

					// generate NIK / unauth ecdh
					case 0x01:
						dap := wdcReq.MSDU[1:]
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
						fmt.Println("For sensor address:", hex.EncodeToString(wdcReq.DSTADDR),
							"generated NIK:", hex.EncodeToString(NIK))

						// the MPDU of the return message
						MPDU := MakeMPDU([]byte{0x01, 0x88}, // fcf, TODO
							[]byte{0xff, 0xff}, []byte{0xff, 0xff},
							wdcReq.DSTPAN, wdcReq.DSTADDR,
							append([]byte{0x02}, // mID NIK response
								dbp...))

						IND := MakeWDCInd(MPDU, trail)

						mutex.Lock()
						ulCh <- IND
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
						dlFrame := DL_AUTH_FRAME{}
						dlFrame.MakeDownlinkFrame(wdcReq)

						if expectedMAC, match := hmac.SHA256HMACVerify(authkey, dlFrame.AUTHDATA, dlFrame.MAC); !match {
							// MAC verification fails, drop
							fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(dlFrame.AUTHDATA),
								"expected:", hex.EncodeToString(expectedMAC))
							return
						}

						dap := dlFrame.PAYLOAD
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
						ulFrame := UL_FRAME{auth: true}
						ulMid := []byte{}

						if mID == 0x03 {
							ulMid = []byte{0x04}
							S = KEYS[:16]
							AK = KEYS[16:]
							fmt.Println("For sensor address:", hex.EncodeToString(dlFrame.DSTADDR),
								"created LTSS:", hex.EncodeToString(S), hex.EncodeToString(AK))
						} else {
							ulMid = []byte{0x06}
							SIK = KEYS[:16]
							SCK = KEYS[16:]
							COUNTER = 0
							fmt.Println("For sensor address:", hex.EncodeToString(dlFrame.DSTADDR),
								"created session keys:", hex.EncodeToString(SIK), hex.EncodeToString(SCK))
						}

						ulFrame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
							dlFrame.DSTPAN, dlFrame.DSTADDR, ulMid, dbp, authkey)
						IND := MakeWDCInd(ulFrame.FRAME, trail)
						mutex.Lock()
						ulCh <- IND
						mutex.Unlock()
						fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

					// update SBK
					case 0x07:
						dlFrame := DL_AUTH_FRAME{}
						dlFrame.MakeDownlinkFrame(wdcReq)

						if expectedMAC, match := hmac.SHA256HMACVerify(SIK, dlFrame.AUTHDATA, dlFrame.MAC); !match {
							// MAC verification fails, drop
							fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(dlFrame.AUTHDATA),
								"expected:", hex.EncodeToString(expectedMAC))
							return
						}

						sbk, err := blockcipher.AESDecryptCBCPKCS7(SCK, dlFrame.PAYLOAD)
						if err != nil {
							fmt.Println("error decrypting SBK:", err.Error())
							return
						}
						fmt.Println("For sensor address:", hex.EncodeToString(dlFrame.DSTADDR),
							"got SBK:", hex.EncodeToString(sbk))

						// construct return MPDU
						ulFrame := UL_FRAME{auth: true}
						ulFrame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
							dlFrame.DSTPAN, dlFrame.DSTADDR, []byte{0x08}, // mID SBK update response
							[]byte{0x00}, // status OK
							SIK)
						IND := MakeWDCInd(ulFrame.FRAME, trail)

						mutex.Lock()
						ulCh <- IND
						mutex.Unlock()
						fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

					// update sensor nodes security policy
					case 0x0B:
						dlFrame := DL_AUTH_FRAME{}
						dlFrame.MakeDownlinkFrame(wdcReq)

						if expectedMAC, match := hmac.SHA256HMACVerify(SIK, dlFrame.AUTHDATA, dlFrame.MAC); !match {
							// MAC verification fails, drop
							fmt.Println("failed MAC verification, MPDU:", hex.EncodeToString(dlFrame.AUTHDATA),
								"expected:", hex.EncodeToString(expectedMAC))
							return
						}

						fmt.Println("For sensor address:", hex.EncodeToString(dlFrame.DSTADDR),
							"got policy:", hex.EncodeToString(dlFrame.PAYLOAD))
						// DL_POLICY = dlFrame.PAYLOAD[0]
						UL_POLICY = dlFrame.PAYLOAD[1]

						// construct return MPDU
						ulFrame := UL_FRAME{auth: true}
						ulFrame.MakeUplinkFrame([]byte{0xff, 0xff}, []byte{0xff, 0xff}, // WDC
							dlFrame.DSTPAN, dlFrame.DSTADDR, []byte{0x0C}, // mID policy update response
							[]byte{0x00}, // status OK
							SIK)
						IND := MakeWDCInd(ulFrame.FRAME, trail)

						mutex.Lock()
						ulCh <- IND
						mutex.Unlock()
						fmt.Println("sent WDC_MAC_DATA_IND:", hex.EncodeToString(IND))

					default:
						fmt.Println("received wrong mID")
						// drop
						return
					}
				}
			}()

		}
	}
	fmt.Println("node processor stopped")
}
