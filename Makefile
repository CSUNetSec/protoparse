all:	build

build:	
	cd cmd/; go build -o ../gobgpdump gobgpdump.go || (echo "running go get"; go get; go get -u; go build -o ../gobgpdump);\
	cd ..;

./gobgpdump: build

clean:
	rm -f gobgpdump;
	rm -f /tmp/testmrt;

test: /tmp/testmrt ./gobgpdump
	./gobgpdump /tmp/testmrt

#fetching one minute of MRT data from the bgpmon.io archive
/tmp/testmrt:
	curl -o /tmp/testmrt http://bgpmon.io/archive/mrt/routeviews2/updates?start=20130101000000\&end=20130101000100
