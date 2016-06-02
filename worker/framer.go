package worker

import "github.com/herrfz/coordnode/crypto/hmac"

const (
	MAC_CMD       = 1 << (7 - 2) // bit order little endian
	ADDR_MODE     = 1 << (7 - 3)
	ACK_REQUESTED = 1 << (7 - 7)
)

type WDC_REQ struct {
	MACCMD bool
	DSTPAN,
	DSTADDR,
	MSDU []byte
	MSDULEN int
}

func (req *WDC_REQ) ParseWDCReq(buf []byte) {
	// parse WDC_MAC_DATA_REQ, cf. EADS MAC Table 29
	TXOPTS := buf[3]
	ADDRMODE := (TXOPTS & ADDR_MODE) == 0
	req.MACCMD = (TXOPTS & MAC_CMD) != 0
	req.DSTPAN = buf[4:6]
	if ADDRMODE { // short addr mode
		req.DSTADDR = buf[6:8] // (16 bits)
		req.MSDULEN = int(buf[8])
		req.MSDU = buf[9:]
	} else { // long addr mode
		req.DSTADDR = buf[6:14] // (64 bits)
		req.MSDULEN = int(buf[14])
		req.MSDU = buf[15:]
	}
}

type DL_AUTH_FRAME struct {
	FCF,
	SEQNR,
	DSTPAN,
	DSTADDR,
	MID,
	PAYLOAD,
	MAC,
	MFR,
	AUTHDATA []byte
}

func (frame *DL_AUTH_FRAME) MakeDownlinkFrame(req WDC_REQ) {
	if len(req.MSDU) < 8 { // must be longer than the MAC
		return
	}

	frame.FCF = []byte{0x04, 0x98} // FCF
	frame.SEQNR = []byte{0x00}     // sequence number, must be set to zero
	frame.DSTPAN = make([]byte, 2)
	copy(frame.DSTPAN, req.DSTPAN)
	frame.DSTADDR = make([]byte, 2)
	copy(frame.DSTADDR, req.DSTADDR)
	frame.MID = []byte{req.MSDU[0]}
	frame.PAYLOAD = make([]byte, (req.MSDULEN-8)-1)
	copy(frame.PAYLOAD, req.MSDU[1:req.MSDULEN-8])
	frame.MAC = make([]byte, 8)
	copy(frame.MAC, req.MSDU[req.MSDULEN-8:]) // MAC := last 8 Bytes of MSDU

	authelms := [][]byte{frame.FCF, frame.SEQNR, frame.DSTPAN, frame.DSTADDR, frame.MID, frame.PAYLOAD}
	for i := 0; i < len(authelms); i++ {
		frame.AUTHDATA = append(frame.AUTHDATA, authelms[i]...)
	}
}

type UL_FRAME struct {
	FCF,
	SEQNR,
	MFR,
	FRAME []byte
	auth bool
}

func (frame *UL_FRAME) MakeUplinkFrame(dstpan, dstaddr, srcpan, srcaddr, mid, payload, authkey []byte) {
	var authdata []byte
	var authelms [][]byte

	frame.FCF = []byte{0x04, 0x98} // FCF, (see Emeric's email)
	frame.SEQNR = []byte{0x00}     // sequence number, must be set to zero
	frame.MFR = []byte{0xde, 0xad} // fake MFR

	if frame.auth {
		authelms = [][]byte{frame.FCF, frame.SEQNR, dstpan, dstaddr, srcpan, srcaddr, mid, payload}
	} else {
		authelms = [][]byte{frame.FCF, frame.SEQNR, dstpan, dstaddr, srcpan, srcaddr, payload}
	}

	for i := 0; i < len(authelms); i++ {
		authdata = append(authdata, authelms[i]...)
	}

	if frame.auth {
		mac := hmac.SHA256HMACGenerate(authkey, authdata)
		frame.FRAME = append(authdata, append(mac, frame.MFR...)...)
	} else {
		frame.FRAME = append(authdata, frame.MFR...)
	}

}

func MakeMPDU(fcf, dstpan, dstaddr, srcpan, srcaddr, msdu []byte) []byte {
	// create MAC_DATA_REQUEST frame from WDC_MAC_DATA_REQUEST command
	MHR := append(fcf,
		0x00) // sequence number, must be set to zero
	dest_addr := append(dstpan, dstaddr...)
	src_addr := append(srcpan, srcaddr...)
	MHR = append(MHR, append(dest_addr, src_addr...)...)

	return append(MHR, append(msdu, []byte{0xde, 0xad}...)...) // fake MFR
}

func MakeWDCInd(mpdu, trail []byte) []byte {
	// create WDC_MAC_DATA_IND command from MAC_DATA_IND frame
	phr := []byte{byte(len(mpdu))}
	ind := append(phr, append(mpdu, trail...)...)
	ind = append([]byte{byte(len(ind) + 1)}, append([]byte{0x19}, // WDC_MAC_DATA_IND
		ind...)...)
	return ind
}
