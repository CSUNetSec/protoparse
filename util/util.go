package util

import (
	"github.com/CSUNetSec/netsec-protobufs/common"
)

func GetIP(a *common.IPAddressWrapper) []byte {
	if a.Ipv4 != nil {
		return a.Ipv4
	} else if a.Ipv6 != nil {
		return a.Ipv6
	}
	return nil
}
