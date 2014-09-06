package worker

func MakeRequest(dstpan, dstaddr, srcpan, srcaddr, msdu []byte) []byte {
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
