package util

import (
	"testing"
)

func TestFlatOpenClose(t *testing.T) {
	pf := NewFlatRecordFile("/dev/null")
	if _, err := pf.Write(nil); err != errNotOpen {
		t.Error("a write in a non open file should fail")
	}
	if err := pf.Close(); err == nil {
		t.Error("a close in a non open file should fail")
	}
	if err := pf.Open(); err != nil {
		t.Error("error opening file: ", err)
	}
	if err := pf.Close(); err != nil {
		t.Error("error closing file: ", err)
	}
}
