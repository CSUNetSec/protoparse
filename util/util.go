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
	var ip net.IP = b
	var buffer bytes.Buffer
	for i := 0; i < len(b) && i < int(mask); i++ {
		buffer.WriteString(fmt.Sprintf("%08b", b[i]))
	}
	pref := ""
	if ip.To4() != nil {
		pref = "v4"
	} else {
		pref = "v6"
	}
	str := buffer.String()
	if len(str) < int(mask) {
		return pref + str
	}
	return pref + str[:mask]
}
