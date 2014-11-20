package worker

import "github.com/herrfz/coordnode/crypto/hmac"

type WDC_REQ struct {
	DSTPAN  []byte
	DSTADDR []byte
	MSDULEN int
	MSDU    []byte
}

func (req *WDC_REQ) ParseWDCReq(buf []byte) {
	// parse WDC_MAC_DATA_REQ, cf. EADS MAC Table 29
	TXOPTS := buf[3]
	ADDRMODE := (TXOPTS >> 3) & 1 // TBC, bit 4 of TXOPTS
	req.DSTPAN = buf[4:6]
	if ADDRMODE == 0 { // short addr mode
		req.DSTADDR = buf[6:8] // (16 bits)
		req.MSDULEN = int(buf[8])
		req.MSDU = buf[9:]
	} else if ADDRMODE == 1 { // long addr mode
		req.DSTADDR = buf[6:14] // (64 bits)
		req.MSDULEN = int(buf[14])
		req.MSDU = buf[15:]
	}
}

type DL_AUTH_FRAME struct {
	MHR      []byte
	SEQNR    []byte
	DSTPAN   []byte
	DSTADDR  []byte
	MID      []byte
	PAYLOAD  []byte
	MAC      []byte
	MFR      []byte
	AUTHDATA []byte
}

func (frame *DL_AUTH_FRAME) MakeDownlinkFrame(req WDC_REQ) {
	frame.MHR = []byte{0x01, 0x08} // FCF, (see Emeric's noserial.patch)
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

	authelms := [][]byte{frame.MHR, frame.SEQNR, frame.DSTPAN, frame.DSTADDR, frame.MID, frame.PAYLOAD}
	for i := 0; i < len(authelms); i++ {
		frame.AUTHDATA = append(frame.AUTHDATA, authelms[i]...)
	}
}

type UL_AUTH_FRAME struct {
	MHR   []byte
	SEQNR []byte
	MFR   []byte
	FRAME []byte
}

func (frame *UL_AUTH_FRAME) MakeUplinkFrame(dstpan, dstaddr, srcpan, srcaddr, mid, payload, authkey []byte) {
	var authdata []byte
	frame.MHR = []byte{0x01, 0x88} // FCF, (see Emeric's noserial.patch)
	frame.SEQNR = []byte{0x00}     // sequence number, must be set to zero
	frame.MFR = []byte{0xde, 0xad} // fake MFR

	authelms := [][]byte{frame.MHR, frame.SEQNR, dstpan, dstaddr, srcpan, srcaddr, mid, payload}
	for i := 0; i < len(authelms); i++ {
		authdata = append(authdata, authelms[i]...)
	}

	mac := hmac.SHA256HMACGenerate(authkey, authdata)
	frame.FRAME = append(authdata, append(mac, frame.MFR...)...)
}

func MakeMPDU(dstpan, dstaddr, srcpan, srcaddr, msdu []byte) []byte {
	// create MAC_DATA_REQUEST frame from WDC_MAC_DATA_REQUEST command
	MHR := []byte{0x01, 0x88, // FCF, (see Emeric's noserial.patch)
		0x00} // sequence number, must be set to zero
	dest_addr := append(dstpan, dstaddr...)
	src_addr := append(srcpan, srcaddr...)
	MHR = append(MHR, append(dest_addr, src_addr...)...)

	return append(MHR, append(msdu, []byte{0xde, 0xad}...)...) // fake MFR
}

func MakeWDCInd(mpdu, trail []byte) []byte {
	// create WDC_MAC_DATA_IND command from MAC_DATA_IND frame
	phr := []byte{byte(len(mpdu))}
	ind := append(phr, append(mpdu, trail...)...)
	ind = append([]byte{byte(len(ind))}, append([]byte{0x19}, // WDC_MAC_DATA_IND
		ind...)...)
	return ind
}
