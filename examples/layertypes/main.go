package main

import (
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/pcap"
)

var flagInput = flag.String("r", "", "input file")

func main() {

	flag.Parse()

	r, err := pcap.OpenOffline(*flagInput)
	if err != nil {
		log.Fatal("failed to open pcap:", err)
	}
	defer r.Close()

	fmt.Println("detected link type:", r.LinkType())

	var layerMap = make(map[string]int64)

	print("processing packets... ")
	for {

		// fetch the next packetdata and packetheader
		// for pcap, currently ZeroCopyReadPacketData() is not supported
		data, _, err := r.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal("reading pcaps failed: ", err)
		}

		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
		for _, l := range p.Layers() {
			layerMap[l.LayerType().String()]++
		}
	}

	fmt.Println()
	for layerName, num := range layerMap {
		fmt.Println(layerName, num)
	}
}
