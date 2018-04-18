package util

import (
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
	inRes{"10.0.0.0/8", "00001010000000000000000000000000"},
	inRes{"128.0.0.0/1", "10000000000000000000000000000000"},
	inRes{"2001:0000:3238:DFE1:63::FEFB/120", "00100000000000010000000000000000001100100011100011011111111000010000000001100011000000000000000000000000000000001111111000000000"}}

func parseIPKeys() []ipMask {
	ret := make([]ipMask, len(ipkeys))

	for i := range ipkeys {
		parts := strings.Split(ipkeys[i].in, "/")
		mask, _ := strconv.ParseUint(parts[1], 10, 32)
		pip := net.ParseIP(parts[0])
		ret[i] = ipMask{pip, uint8(mask)}
	}

	return ret
}

func TestIPToRadixKey(t *testing.T) {
	ipl := parseIPKeys()
	for i := range ipl {
		key := IpToRadixkey(ipl[i].ip, ipl[i].mask)
		if ipkeys[i].out != key {
			t.Errorf("IP:%s Key:%s Expected:%s", ipkeys[i].in, key, ipkeys[i].out)
		}
	}
}
