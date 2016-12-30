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
	if err := pf.OpenRead(); err != nil {
		t.Error("error opening file: ", err)
	}
	if err := pf.OpenWrite(); err == nil {
		t.Error("test should fail since file is already open")
	}
	if err := pf.Close(); err != nil {
		t.Error("error closing file: ", err)
	}
	if err := pf.OpenWrite(); err != nil {
		t.Error("Error opening file: ", err)
	}
	if err := pf.Close(); err != nil {
		t.Error("error closing file: ", err)
	}
}

func TestFootedOpenClose(t *testing.T) {
	pf := NewFootedRecordFile("/tmp/testflatfooted")
	if err := pf.OpenWrite(); err != nil {
		t.Error("Error opening file: ", err)
	}
	if err := pf.Close(); err != nil {
		t.Error("error closing file: ", err)
	}
}
