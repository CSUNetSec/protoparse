all:	build

build:	build-proto
	go build cmd/gobgpdump.go;

build-proto: netsec-protobufs
	mkdir pb;
	protoc --proto_path=netsec-protobufs/ --go_out=import_path=pb:netsec-protobufs/ netsec-protobufs/protocol/bgp/bgp.proto netsec-protobufs/common/common.proto;
	find ./netsec-protobufs -name "*.go" -exec cp {} pb/ \;

netsec-protobufs:
	git clone https://github.com/CSUNetSec/netsec-protobufs;

clean:
	rm -rf pb/ netsec-protobufs/;
	rm -f gobgpdump;
	rm -f /tmp/testmrt;

test: /tmp/testmrt
	./gobgpdump /tmp/testmrt

#fetching one minute of MRT data from the bgpmon.io archive
/tmp/testmrt:
	curl -o /tmp/testmrt http://bgpmon.io/archive/mrt/routeviews2/updates?start=20130101000000\&end=20130101000100
