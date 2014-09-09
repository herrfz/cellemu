package worker

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type testpair struct {
	msg Message
	buf []byte
}

var tests = []testpair{
	{Message{1, []byte{}}, []byte{0x01, 0x03, 0xfb}},
	{Message{2, []byte{}}, []byte{0x02, 0x03, 0xfa}},
	{Message{3, []byte{0xca, 0xfe}}, []byte{0x03, 0x05, 0xca, 0xfe, 0x2f}},
	{Message{4, []byte{0xca, 0xfe}}, []byte{0x04, 0x05, 0xca, 0xfe, 0x2e}},
}

func TestGenerateMessage(t *testing.T) {
	for _, test := range tests {
		if buf := test.msg.GenerateMessage(); !bytes.Equal(buf, test.buf) {
			t.Errorf("wrong output: %v, expected: %v", hex.EncodeToString(buf), hex.EncodeToString(test.buf))
		}
	}
}

func TestParseBuffer(t *testing.T) {
	for _, test := range tests {
		msg := Message{}

		err := msg.ParseBuffer(test.buf)
		if err != nil {
			t.Errorf("error parsing: %v", err.Error())
		}

		if msg.mtype != test.msg.mtype {
			t.Errorf("wrong mtype: %v, expected: %v", msg.mtype, test.msg.mtype)
		}

		if !bytes.Equal(msg.data, test.msg.data) {
			t.Errorf("wrong data: %v, expected: %v", hex.EncodeToString(msg.data), hex.EncodeToString(test.msg.data))
		}
	}
}
