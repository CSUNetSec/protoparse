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
	if a.Ipv4 != nil {
		return a.Ipv4
	} else if a.Ipv6 != nil {
		return a.Ipv6
	}
	return nil
}

//creates a binary string representation of an IP
//address. the length is 32 chars for ipv4 and 128
//chars for ipv6. The mask is applied and zeroes out
//the bits it masks out on the resulting string.
func IpToRadixkey(b []byte, mask uint8) string {
	var (
		ip     net.IP = b
		buffer bytes.Buffer
	)
	if len(b) == 0 || len(ip) == 0 { // a misparsed ip probably.
		return ""
	}

	if ip.To4() != nil {
		if mask > 32 { //misparsed?
			return ""
		}
		ip = ip.Mask(net.CIDRMask(int(mask), 32)).To4()
	} else {
		if mask > 128 { //misparsed?
			return ""
		}
		ip = ip.Mask(net.CIDRMask(int(mask), 128)).To16()
	}

	for i := 0; i < len(ip); i++ {
		fmt.Fprintf(&buffer, "%08b", ip[i])
	}
	return buffer.String()[:mask]
}

//helper that just converts a possible mask string
//to a 10 based uint8.
func MaskStrToUint8(m string) (uint8, error) {
	mask, err := strconv.ParseUint(m, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint8(mask), nil
}

//PrefixTree holds a radix tree which clients
//can insert ips and masks in , and  also lookup
//for their existence.
type PrefixTree struct {
	rt *radix.Tree
}

func NewPrefixTree() PrefixTree {
	return PrefixTree{
		rt: radix.New(),
	}
}

func (pt PrefixTree) Add(ip net.IP, mask uint8) {
	keystr := IpToRadixkey(ip, mask)
	pt.rt.Insert(keystr, true)
}

func (pt PrefixTree) ContainsIpMask(ip net.IP, mask uint8) bool {
	keystr := IpToRadixkey(ip, mask)
	if _, _, found := pt.rt.LongestPrefix(keystr); found {
		return true
	}
	return false
}
