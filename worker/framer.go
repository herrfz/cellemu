package worker

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
