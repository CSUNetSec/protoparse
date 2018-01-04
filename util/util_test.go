package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

type inRes struct {
	in  string
	out string
}

type ipMask struct {
	ip   net.IP
	mask uint8
}

var ipkeys = []inRes{inRes{"10.0.0.1/16", "00001010000000000000000000000000"},
	inRes{"10.0.0.1/32", "00001010000000000000000000000001"},
	inRes{"10.0.0.2/32", "00001010000000000000000000000010"},
	inRes{"10.0.12.0/24", "00001010000000000000110000000000"},
	inRes{"::FFFF:192.168.1.12/32", "11000000101010000000000100001100"},
	inRes{"2001:0000:3238:DFE1:63::FEFB/120", "00100000000000010000000000000000001100100011100011011111111000010000000001100011000000000000000000000000000000001111111000000000"}}

func makeList(list string) []ipMask {
	slashField := func(r rune) bool {
		return r == '/'
	}
	ipmaskstrs := strings.Fields(list)
	ret := make([]ipMask, len(ipmaskstrs))
	for ipi := range ipmaskstrs {
		ipPairs := strings.FieldsFunc(ipmaskstrs[ipi], slashField)
		mask, _ := strconv.ParseUint(ipPairs[1], 10, 32)
		pip := net.ParseIP(ipPairs[0])
		fmt.Printf("parsed ip:%s\n", pip)
		ret[ipi] = ipMask{pip, uint8(mask)}
	}
	return ret
}

func TestIPToRadixKey(t *testing.T) {
	ipl := makeList("10.0.0.1/16 10.0.0.1/32 10.0.0.2/32 10.0.12.0/24 ::FFFF:192.168.1.12/32 2001:0000:3238:DFE1:63::FEFB/120")
	var keys []string
	for i := range ipl {
		key := IpToRadixkey(ipl[i].ip, ipl[i].mask)
		fmt.Printf("ip:%s is key:%s\n", ipl[i].ip, key)
		keys = append(keys, key)
	}
	for ki := range keys {
		if keys[ki] != ipkeys[ki].out {
			t.Errorf("ip:%s key:%s expected:%s", ipl[ki].ip, keys[ki], ipkeys[ki].out)
		}
	}
}
