package util

import (
	"bytes"
	"fmt"
	pbcom "github.com/CSUNetSec/netsec-protobufs/common"
	"net"
)

func GetIP(a *pbcom.IPAddressWrapper) []byte {
	if a.Ipv4 != nil {
		return a.Ipv4
	} else if a.Ipv6 != nil {
		return a.Ipv6
	}
	return nil
}

func IpToRadixkey(b []byte, mask uint8) string {
	var (
		ip     net.IP = b
		max    int
		buffer bytes.Buffer
	)
	if len(b) == 0 { // a misparsed ip probably.
		return ""
	}

	if ip.To4() != nil {
		ip = ip.Mask(net.CIDRMask(int(mask), 32)).To4()
		max = 32
	} else {
		ip = ip.Mask(net.CIDRMask(int(mask), 128)).To16()
		max = 128
	}

	for i := 0; i < len(ip) && i < int(max); i++ {
		fmt.Fprintf(&buffer, "%08b", ip[i])
	}
	return buffer.String()[:max]
}
