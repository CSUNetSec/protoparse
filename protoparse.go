package protoparse

import (
	pbbgp "github.com/CSUNetSec/netsec-protobufs/protocol/bgp"
)

//A pbval is an interface that takes a byte slice and populates the
//underlying pb. all supported pbs must implement it.
type PbVal interface {
	Parse() (PbVal, error)
	String() string
}

type BGPUpdater interface {
	PbVal
	GetUpdate() *pbbgp.BGPUpdate
}

type BGP4MPHeaderer interface {
	PbVal
	GetHeader() *pbbgp.BGP4MPHeader
}

type MRTHeaderer interface {
	PbVal
	GetHeader() *pbbgp.MrtHeader
}
