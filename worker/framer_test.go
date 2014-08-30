package worker

import (
    "bytes"
    "encoding/hex"
    "testing"
)

func TestMakeRequest(t *testing.T) {
    dstpan := []byte{0x1c, 0xaa}
    dstaddr := []byte{0x00, 0x00}
    srcpan := []byte{0xff, 0xff}
    srcaddr := []byte{0xff, 0xff}
    msdu := []byte{0xde, 0xad, 0xbe, 0xef}
    out := []byte{0x01, 0x88, 0x00, 0x1c, 0xaa, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}

    if mpdu := MakeRequest(dstpan, dstaddr, srcpan, srcaddr, msdu); !bytes.Equal(mpdu, out) {
        t.Errorf("TestMakeRequest wrong output: %v, expected: %v", hex.EncodeToString(mpdu), hex.EncodeToString(out))
    }
}

func TestMakeWDCInd(t *testing.T) {
    psdu := []byte{0xde, 0xad, 0xbe, 0xef}
    trail := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    out := []byte{0x0b, 0x19, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

    if ind := MakeWDCInd(psdu, trail); !bytes.Equal(ind, out) {
        t.Errorf("TestMakeWDCInd wrong output: %v, expected: %v", hex.EncodeToString(ind), hex.EncodeToString(out))
    }
}