package util

import (
	"bytes"
	"fmt"
	pbcom "github.com/CSUNetSec/netsec-protobufs/common"
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
	var buffer bytes.Buffer
	for i := 0; i < len(b) && i < int(mask); i++ {
		buffer.WriteString(fmt.Sprintf("%08b", b[i]))
	}
	str := buffer.String()
	if len(str) < int(mask) {
		return str
	}
	return str[:mask]
}
