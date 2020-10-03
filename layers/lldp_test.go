// Copyright 2020 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.
package layers

import (
	"reflect"
	"testing"

	"github.com/dreadl0ck/gopacket"
)

// testPacketLLDP is the packet:
//   13:03:20.982430 LLDP, length 222: Switch1
//   	0x0000:  0180 c200 000e 001b 1b02 e61f 88cc 0208  ................
//   	0x0010:  0773 7769 7463 6831 0409 0770 6f72 742d  .switch1...port-
//   	0x0020:  3030 3106 0200 1408 2d53 6965 6d65 6e73  001.....-Siemens
//   	0x0030:  2c20 5349 4d41 5449 4320 4e45 542c 2045  ,.SIMATIC.NET,.E
//   	0x0040:  7468 6572 6e65 7420 5377 6974 6368 2050  thernet.Switch.P
//   	0x0050:  6f72 7420 3031 0a07 5377 6974 6368 310c  ort.01..Switch1.
//   	0x0060:  4c53 6965 6d65 6e73 2c20 5349 4d41 5449  LSiemens,.SIMATI
//   	0x0070:  4320 4e45 542c 2053 4341 4c41 4e43 4520  C.NET,.SCALANCE.
//   	0x0080:  5832 3132 2d32 2c20 3647 4b35 2032 3132  X212-2,.6GK5.212
//   	0x0090:  2d32 4242 3030 2d32 4141 332c 2048 573a  -2BB00-2AA3,.HW:
//   	0x00a0:  2037 2c20 4657 3a20 5634 2e30 320e 0400  .7,.FW:.V4.02...
//   	0x00b0:  8000 8010 1405 018d 5100 be02 0000 0001  ........Q.......
//   	0x00c0:  082b 0601 0401 81c0 6efe 0800 0ecf 0200  .+......n.......
//   	0x00d0:  0000 00fe 0a00 0ecf 0500 1b1b 02e6 1efe  ................
//   	0x00e0:  0900 120f 0103 6c00 0010 0000            ......l.....
var testPacketLLDP = []byte{
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x1b, 0x1b, 0x02, 0xe6, 0x1f, 0x88, 0xcc, 0x02, 0x08,
	0x07, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x31, 0x04, 0x09, 0x07, 0x70, 0x6f, 0x72, 0x74, 0x2d,
	0x30, 0x30, 0x31, 0x06, 0x02, 0x00, 0x14, 0x08, 0x2d, 0x53, 0x69, 0x65, 0x6d, 0x65, 0x6e, 0x73,
	0x2c, 0x20, 0x53, 0x49, 0x4d, 0x41, 0x54, 0x49, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x2c, 0x20, 0x45,
	0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x20, 0x50,
	0x6f, 0x72, 0x74, 0x20, 0x30, 0x31, 0x0a, 0x07, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x31, 0x0c,
	0x4c, 0x53, 0x69, 0x65, 0x6d, 0x65, 0x6e, 0x73, 0x2c, 0x20, 0x53, 0x49, 0x4d, 0x41, 0x54, 0x49,
	0x43, 0x20, 0x4e, 0x45, 0x54, 0x2c, 0x20, 0x53, 0x43, 0x41, 0x4c, 0x41, 0x4e, 0x43, 0x45, 0x20,
	0x58, 0x32, 0x31, 0x32, 0x2d, 0x32, 0x2c, 0x20, 0x36, 0x47, 0x4b, 0x35, 0x20, 0x32, 0x31, 0x32,
	0x2d, 0x32, 0x42, 0x42, 0x30, 0x30, 0x2d, 0x32, 0x41, 0x41, 0x33, 0x2c, 0x20, 0x48, 0x57, 0x3a,
	0x20, 0x37, 0x2c, 0x20, 0x46, 0x57, 0x3a, 0x20, 0x56, 0x34, 0x2e, 0x30, 0x32, 0x0e, 0x04, 0x00,
	0x80, 0x00, 0x80, 0x10, 0x14, 0x05, 0x01, 0x8d, 0x51, 0x00, 0xbe, 0x02, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xc0, 0x6e, 0xfe, 0x08, 0x00, 0x0e, 0xcf, 0x02, 0x00,
	0x00, 0x00, 0x00, 0xfe, 0x0a, 0x00, 0x0e, 0xcf, 0x05, 0x00, 0x1b, 0x1b, 0x02, 0xe6, 0x1e, 0xfe,
	0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0x6c, 0x00, 0x00, 0x10, 0x00, 0x00,
}

func TestPacketLLDP(t *testing.T) {
	p := gopacket.NewPacket(testPacketLLDP, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeLinkLayerDiscovery, LayerTypeLinkLayerDiscoveryInfo}, t)
	if got, ok := p.Layer(LayerTypeLinkLayerDiscoveryInfo).(*LinkLayerDiscoveryInfo); ok {
		want := &LinkLayerDiscoveryInfo{
			PortDescription: "Siemens, SIMATIC NET, Ethernet Switch Port 01",
			SysName:         "Switch1",
			SysDescription:  "Siemens, SIMATIC NET, SCALANCE X212-2, 6GK5 212-2BB00-2AA3, HW: 7, FW: V4.02",
			SysCapabilities: LLDPSysCapabilities{
				SystemCap:  LLDPCapabilities{StationOnly: true},
				EnabledCap: LLDPCapabilities{StationOnly: true},
			},
			MgmtAddress: LLDPMgmtAddress{
				Subtype:          0x1,
				Address:          []uint8{0x8d, 0x51, 0x0, 0xbe},
				InterfaceSubtype: 0x2,
				InterfaceNumber:  0x1,
				OID:              "+\x06\x01\x04\x01\x81\xc0n",
			},
			OrgTLVs: []LLDPOrgSpecificTLV{
				{OUI: 0xecf, SubType: 0x2, Info: []uint8{0x0, 0x0, 0x0, 0x0}},
				{OUI: 0xecf, SubType: 0x5, Info: []uint8{0x0, 0x1b, 0x1b, 0x2, 0xe6, 0x1e}},
				{OUI: 0x120f, SubType: 0x1, Info: []uint8{0x3, 0x6c, 0x0, 0x0, 0x10}},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("LLDP Info packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No LLDP Info layer type found in packet")
	}
}

func BenchmarkDecodePacketLLDP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketLLDP, LinkTypeEthernet, gopacket.NoCopy)
	}
}
