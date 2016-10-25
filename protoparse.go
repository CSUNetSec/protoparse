package protoparse

//A pbval is an interface that takes a byte slice and populates the
//underlying pb. all supported pbs must implement it.
type PbVal interface {
	Parse() (PbVal, error)
	String() string
}
