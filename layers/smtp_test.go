// Copyright 2019 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/dreadl0ck/gopacket"
	"reflect"
	"testing"
)

var exampleSMTPCommandMessage = []byte{
	0x45, 0x48, 0x4c, 0x4f, 0x20, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x66, 0x61, 0x73, 0x74, 0x72, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x69, 0x6f, 0x0d, 0x0a,
}
var exampleSMTPCommandMessage2 = []byte{
	0x53, 0x54, 0x41, 0x52, 0x54, 0x54, 0x4c, 0x53, 0x0d, 0x0a,
}

var exampleSMTPResponseMessage = []byte{
	0x32, 0x35, 0x30, 0x2d, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x66, 0x61, 0x73, 0x74, 0x72, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x69, 0x6f, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d, 0x50, 0x49,
	0x50, 0x45, 0x4c, 0x49, 0x4e, 0x49, 0x4e, 0x47, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d, 0x53, 0x49,
	0x5a, 0x45, 0x20, 0x31, 0x30, 0x34, 0x38, 0x35, 0x37, 0x36, 0x30, 0x30, 0x0d, 0x0a, 0x32, 0x35,
	0x30, 0x2d, 0x45, 0x54, 0x52, 0x4e, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d, 0x53, 0x54, 0x41, 0x52,
	0x54, 0x54, 0x4c, 0x53, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d, 0x45, 0x4e, 0x48, 0x41, 0x4e, 0x43,
	0x45, 0x44, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x0d, 0x0a, 0x32,
	0x35, 0x30, 0x2d, 0x38, 0x42, 0x49, 0x54, 0x4d, 0x49, 0x4d, 0x45, 0x0d, 0x0a, 0x32, 0x35, 0x30,
	0x20, 0x44, 0x53, 0x4e, 0x0d, 0x0a,
}

var exampleSMTPResponseMessage2 = []byte{
	0x32, 0x32, 0x30, 0x20, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x6c,
	0x73, 0x0d, 0x0a,
}

var exampleSMTPDataContentMessage = []byte{
	0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x6a, 0x61, 0x6e, 0x2e, 0x70, 0x68, 0x69, 0x6c, 0x69, 0x70,
	0x70, 0x2e, 0x62, 0x65, 0x6e, 0x65, 0x63, 0x6b, 0x65, 0x40, 0x6a, 0x70, 0x62, 0x65, 0x2e, 0x64,
	0x65, 0x0d, 0x0a, 0x54, 0x6f, 0x3a, 0x20, 0x74, 0x65, 0x73, 0x74, 0x40, 0x6a, 0x70, 0x62, 0x65,
	0x2e, 0x64, 0x65, 0x0d, 0x0a, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x20, 0x54, 0x65,
	0x73, 0x74, 0x0d, 0x0a, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65,
	0x73, 0x74, 0x20, 0x6d, 0x61, 0x69, 0x6c, 0x21, 0x0d, 0x0a,
}

func TestSMTPCommandDecode(t *testing.T) {
	p := gopacket.NewPacket(exampleSMTPCommandMessage, LayerTypeSMTP, gopacket.Default)

	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeSMTP}, t)
	got := p.ApplicationLayer().(*SMTP)

	want := &SMTP{
		BaseLayer:     BaseLayer{Contents: []uint8{0x45, 0x48, 0x4c, 0x4f, 0x20, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x66, 0x61, 0x73, 0x74, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x69, 0x6f, 0xd, 0xa}, Payload: []uint8(nil)},
		IsResponse:    false,
		ResponseLines: []SMTPResponse(nil),
		Command: SMTPCommand{
			Command:   SMTPCommandTypeEHLO,
			Parameter: "mail.fastresponse.io",
		},
		IsEncrypted: false,
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("SMTP layer mismatch, \nwant:\n\n%#v\ngot:\n\n\n%#v\n\n", want, got)
	}
}

func TestSMTPCommandDecode2(t *testing.T) {
	p := gopacket.NewPacket(exampleSMTPCommandMessage2, LayerTypeSMTP, gopacket.Default)

	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeSMTP}, t)
	got := p.ApplicationLayer().(*SMTP)

	want := &SMTP{
		BaseLayer:     BaseLayer{Contents: []uint8{0x53, 0x54, 0x41, 0x52, 0x54, 0x54, 0x4c, 0x53, 0x0d, 0x0a}, Payload: []uint8(nil)},
		IsResponse:    false,
		ResponseLines: []SMTPResponse(nil),
		Command: SMTPCommand{
			Command: SMTPCommandTypeSTARTTLS,
		},
		IsEncrypted: false,
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("SMTP layer mismatch, \nwant:\n\n%#v\ngot:\n\n\n%#v\n\n", want, got)
	}
}

func TestSMTPResponseDecode(t *testing.T) {
	p := gopacket.NewPacket(exampleSMTPResponseMessage, LayerTypeSMTP, gopacket.Default)

	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeSMTP}, t)

	got := p.ApplicationLayer().(*SMTP)

	want := &SMTP{
		BaseLayer:  BaseLayer{Contents: []uint8{0x32, 0x35, 0x30, 0x2d, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x66, 0x61, 0x73, 0x74, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x69, 0x6f, 0xd, 0xa, 0x32, 0x35, 0x30, 0x2d, 0x50, 0x49, 0x50, 0x45, 0x4c, 0x49, 0x4e, 0x49, 0x4e, 0x47, 0xd, 0xa, 0x32, 0x35, 0x30, 0x2d, 0x53, 0x49, 0x5a, 0x45, 0x20, 0x31, 0x30, 0x34, 0x38, 0x35, 0x37, 0x36, 0x30, 0x30, 0xd, 0xa, 0x32, 0x35, 0x30, 0x2d, 0x45, 0x54, 0x52, 0x4e, 0xd, 0xa, 0x32, 0x35, 0x30, 0x2d, 0x53, 0x54, 0x41, 0x52, 0x54, 0x54, 0x4c, 0x53, 0xd, 0xa, 0x32, 0x35, 0x30, 0x2d, 0x45, 0x4e, 0x48, 0x41, 0x4e, 0x43, 0x45, 0x44, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x43, 0x4f, 0x44, 0x45, 0x53, 0xd, 0xa, 0x32, 0x35, 0x30, 0x2d, 0x38, 0x42, 0x49, 0x54, 0x4d, 0x49, 0x4d, 0x45, 0xd, 0xa, 0x32, 0x35, 0x30, 0x20, 0x44, 0x53, 0x4e, 0xd, 0xa}, Payload: []uint8(nil)},
		IsResponse: true,
		ResponseLines: []SMTPResponse{
			SMTPResponse{ResponseCode: 250, Parameter: "mail.fastresponse.io"},
			SMTPResponse{ResponseCode: 250, Parameter: "PIPELINING"},
			SMTPResponse{ResponseCode: 250, Parameter: "SIZE 104857600"},
			SMTPResponse{ResponseCode: 250, Parameter: "ETRN"},
			SMTPResponse{ResponseCode: 250, Parameter: "STARTTLS"},
			SMTPResponse{ResponseCode: 250, Parameter: "ENHANCEDSTATUSCODES"},
			SMTPResponse{ResponseCode: 250, Parameter: "8BITMIME"},
			SMTPResponse{ResponseCode: 250, Parameter: "DSN"},
		},
		Command:     SMTPCommand{},
		IsEncrypted: false,
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("SMTP layer mismatch, \nwant:\n\n%#v\ngot:\n\n\n%#v\n\n", want, got)
	}
}

func TestSMTPResponseDecode2(t *testing.T) {
	p := gopacket.NewPacket(exampleSMTPResponseMessage2, LayerTypeSMTP, gopacket.Default)

	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeSMTP}, t)

	got := p.ApplicationLayer().(*SMTP)

	want := &SMTP{
		BaseLayer:     BaseLayer{Contents: []uint8{0x32, 0x32, 0x30, 0x20, 0x72, 0x65, 0x61, 0x64, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x6c, 0x73, 0xd, 0xa}, Payload: []uint8(nil)},
		IsResponse:    true,
		ResponseLines: []SMTPResponse{SMTPResponse{ResponseCode: 220, Parameter: "ready for tls"}},
		Command:       SMTPCommand{},
		IsEncrypted:   false,
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("SMTP layer mismatch, \nwant:\n\n%#v\ngot:\n\n\n%#v\n\n", want, got)
	}
}

func TestSMTPDataContentDecode(t *testing.T) {
	p := gopacket.NewPacket(exampleSMTPDataContentMessage, LayerTypeSMTP, gopacket.Default)

	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeSMTP}, t)

	got := p.ApplicationLayer().(*SMTP)

	want := &SMTP{
		BaseLayer: BaseLayer{
			Contents: []uint8{0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x6a, 0x61, 0x6e, 0x2e, 0x70, 0x68, 0x69, 0x6c, 0x69, 0x70, 0x70, 0x2e, 0x62, 0x65, 0x6e, 0x65, 0x63, 0x6b, 0x65, 0x40, 0x6a, 0x70, 0x62, 0x65, 0x2e, 0x64, 0x65, 0xd, 0xa, 0x54, 0x6f, 0x3a, 0x20, 0x74, 0x65, 0x73, 0x74, 0x40, 0x6a, 0x70, 0x62, 0x65, 0x2e, 0x64, 0x65, 0xd, 0xa, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x20, 0x54, 0x65, 0x73, 0x74, 0xd, 0xa, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x61, 0x69, 0x6c, 0x21, 0xd, 0xa},
			Payload:  []uint8{0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20, 0x6a, 0x61, 0x6e, 0x2e, 0x70, 0x68, 0x69, 0x6c, 0x69, 0x70, 0x70, 0x2e, 0x62, 0x65, 0x6e, 0x65, 0x63, 0x6b, 0x65, 0x40, 0x6a, 0x70, 0x62, 0x65, 0x2e, 0x64, 0x65, 0xd, 0xa, 0x54, 0x6f, 0x3a, 0x20, 0x74, 0x65, 0x73, 0x74, 0x40, 0x6a, 0x70, 0x62, 0x65, 0x2e, 0x64, 0x65, 0xd, 0xa, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x20, 0x54, 0x65, 0x73, 0x74, 0xd, 0xa, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x61, 0x69, 0x6c, 0x21, 0xd},
		},
		IsEncrypted:   false,
		IsResponse:    false,
		ResponseLines: []SMTPResponse(nil),
		Command:       SMTPCommand{Command: SMTPCommandTypeMSG, Parameter: ""},
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("SMTP layer mismatch, \nwant:\n\n%#v\ngot:\n\n\n%#v\n\n", want, got)
	}
}