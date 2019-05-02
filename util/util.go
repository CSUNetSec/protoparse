package util

import (
	"bytes"
	"fmt"
	pbcom "github.com/CSUNetSec/netsec-protobufs/common"
	radix "github.com/armon/go-radix"
	"net"
	"strconv"
)

func GetIP(a *pbcom.IPAddressWrapper) []byte {
	if a.IPv4 != nil {
		return a.IPv4
	} else if a.IPv6 != nil {
		return a.IPv6
	}
	return nil
}

// IPToRadixkey creates a binary string representation of an IP
// address. the length is 32 chars for IPv4 and 128
// chars for IPv6. The mask is applied and zeroes out
// the bits it masks out on the resulting string.
func IPToRadixkey(b []byte, mask uint8) string {
	var (
		IP     net.IP = b
		buffer bytes.Buffer
	)
	if len(b) == 0 || len(IP) == 0 { // a misparsed IP probably.
		return ""
	}

	if IP.To4() != nil {
		if mask > 32 { //misparsed?
			return ""
		}
		IP = IP.Mask(net.CIDRMask(int(mask), 32)).To4()
	} else {
		if mask > 128 { //misparsed?
			return ""
		}
		IP = IP.Mask(net.CIDRMask(int(mask), 128)).To16()
	}

	for i := 0; i < len(IP); i++ {
		fmt.Fprintf(&buffer, "%08b", IP[i])
	}
	return buffer.String()[:mask]
}

// MaskStrToUint8 is a helper that just converts a possible mask string
// to a 10 based uint8.
func MaskStrToUint8(m string) (uint8, error) {
	mask, err := strconv.ParseUint(m, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint8(mask), nil
}

// PrefixTree holds a radix tree which clients
// can insert IPs and masks in , and  also lookup
// for their existence.
type PrefixTree struct {
	rt *radix.Tree
}

// NewPrefixTree creates a new PrefixTree with an empty radix tree.
func NewPrefixTree() PrefixTree {
	return PrefixTree{
		rt: radix.New(),
	}
}

// Add adds an IP and a mask to that PrefixTree.
func (pt PrefixTree) Add(IP net.IP, mask uint8) {
	keystr := IPToRadixkey(IP, mask)
	pt.rt.Insert(keystr, true)
}

// ContainsIPMask checks for the existance of that IP and mask in the PrefixTree.
// It performs a longest prefix match and if it is found it retuns true.
func (pt PrefixTree) ContainsIPMask(IP net.IP, mask uint8) bool {
	keystr := IPToRadixkey(IP, mask)
	if _, _, found := pt.rt.LongestPrefix(keystr); found {
		return true
	}
	return false
}
