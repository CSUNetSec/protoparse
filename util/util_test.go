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

var ipkeys = []inRes{inRes{"10.0.0.1/16", "0000101000000000"},
	inRes{"10.0.0.1/32", "00001010000000000000000000000001"},
	inRes{"10.0.0.2/32", "00001010000000000000000000000010"},
	inRes{"10.0.12.0/24", "000010100000000000001100"},
	inRes{"::FFFF:192.168.1.12/32", "11000000101010000000000100001100"},
	inRes{"10.0.0.0/8", "00001010"},
	inRes{"0.0.0.0/0", ""},
	inRes{"128.0.0.0/1", "1"},
	inRes{"2001:0000:3238:DFE1:63::FEFB/120", "001000000000000100000000000000000011001000111000110111111110000100000000011000110000000000000000000000000000000011111110"}}

func parseIP(s string) ipMask {
	parts := strings.Split(s, "/")
	mask, _ := strconv.ParseUint(parts[1], 10, 32)
	pip := net.ParseIP(parts[0])
	return ipMask{pip, uint8(mask)}
}

func TestIPToRadixKey(t *testing.T) {
	for i := range ipkeys {
		im := parseIP(ipkeys[i].in)
		key := IpToRadixkey(im.ip, im.mask)

		if ipkeys[i].out != key {
			t.Errorf("IP:%s Key:%s Expected:%s", ipkeys[i].in, key, ipkeys[i].out)
		}
	}
}

type prefTester struct {
	parentIp string
	childIp  string
	isChild  bool
}

var prefTests = []prefTester{prefTester{"10.0.0.0/16", "10.0.0.0/15", false},
	prefTester{"100.12.10.0/24", "100.12.10.8/25", true},
	prefTester{"/0", "/0", true}}

func TestPrefixTree(t *testing.T) {
	for _, curTest := range prefTests {
		pt := NewPrefixTree()
		par := parseIP(curTest.parentIp)
		pt.Add(par.ip, par.mask)
		child := parseIP(curTest.childIp)
		isC := pt.ContainsIpMask(child.ip, child.mask)
		if isC != curTest.isChild {
			t.Errorf("Parent:%s Child:%s Expected:%t Got:%t", curTest.parentIp, curTest.childIp, curTest.isChild, isC)
		}
	}
}

func TestEmptyPrefixTree(t *testing.T) {
	pt := NewPrefixTree()
	pt.Add(net.IP{0, 0, 0, 0}, 0)
	if !pt.ContainsIpMask(net.IP{1, 2, 3, 4}, 32) {
		t.Errorf("Contains error")
	}
}
