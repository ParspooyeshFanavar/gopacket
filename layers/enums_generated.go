// Copyright 2012 Google, Inc. All rights reserved.

package layers

// Created by gen2.go, don't edit manually
// Generated at 2022-08-14 17:04:22.83449 +0200 CEST m=+0.008730827

import (
	"fmt"

	"github.com/ParspooyeshFanavar/gopacket"
)

func init() {
	initUnknownTypesForLinkType()
	initUnknownTypesForEthernetType()
	initUnknownTypesForPPPType()
	initUnknownTypesForIPProtocol()
	initUnknownTypesForSCTPChunkType()
	initUnknownTypesForPPPoECode()
	initUnknownTypesForFDDIFrameControl()
	initUnknownTypesForEAPOLType()
	initUnknownTypesForProtocolFamily()
	initUnknownTypesForDot11Type()
	initUnknownTypesForUSBTransportType()
	initActualTypeData()
}

// Decoder calls LinkTypeMetadata.DecodeWith's decoder.
func (a LinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 277 {
		errDecoder := errorDecoderForLinkType(a)
		return &errDecoder
	}

	return LinkTypeMetadata[a].DecodeWith.Decode(data, p)
}

// String returns LinkTypeMetadata.Name.
func (a LinkType) String() string {
	if int(a) >= 277 {
		return "UnknownLinkType"
	}

	return LinkTypeMetadata[a].Name
}

// LayerType returns LinkTypeMetadata.LayerType.
func (a LinkType) LayerType() gopacket.LayerType {
	if int(a) >= 277 {
		return 0
	}

	return LinkTypeMetadata[a].LayerType
}

type errorDecoderForLinkType int

func (a *errorDecoderForLinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForLinkType) Error() string {
	return fmt.Sprintf("Unable to decode LinkType %d", int(*a))
}

var (
	errorDecodersForLinkType [277]errorDecoderForLinkType
	LinkTypeMetadata         [277]EnumMetadata
)

func initUnknownTypesForLinkType() {
	for i := 0; i < 277; i++ {
		errorDecodersForLinkType[i] = errorDecoderForLinkType(i)
		LinkTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForLinkType[i],
			Name:       "UnknownLinkType",
		}
	}
}

// Decoder calls EthernetTypeMetadata.DecodeWith's decoder.
func (a EthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 65536 {
		errDecoder := errorDecoderForEthernetType(a)
		return &errDecoder
	}

	return EthernetTypeMetadata[a].DecodeWith.Decode(data, p)
}

// String returns EthernetTypeMetadata.Name.
func (a EthernetType) String() string {
	if int(a) >= 65536 {
		return "UnknownEthernetType"
	}

	return EthernetTypeMetadata[a].Name
}

// LayerType returns EthernetTypeMetadata.LayerType.
func (a EthernetType) LayerType() gopacket.LayerType {
	if int(a) >= 65536 {
		return 0
	}

	return EthernetTypeMetadata[a].LayerType
}

type errorDecoderForEthernetType int

func (a *errorDecoderForEthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForEthernetType) Error() string {
	return fmt.Sprintf("Unable to decode EthernetType %d", int(*a))
}

var (
	errorDecodersForEthernetType [65536]errorDecoderForEthernetType
	EthernetTypeMetadata         [65536]EnumMetadata
)

func initUnknownTypesForEthernetType() {
	for i := 0; i < 65536; i++ {
		errorDecodersForEthernetType[i] = errorDecoderForEthernetType(i)
		EthernetTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForEthernetType[i],
			Name:       "UnknownEthernetType",
		}
	}
}

// Decoder calls PPPTypeMetadata.DecodeWith's decoder.
func (a PPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 65536 {
		errDecoder := errorDecoderForPPPType(a)
		return &errDecoder
	}

	return PPPTypeMetadata[a].DecodeWith.Decode(data, p)
}

// String returns PPPTypeMetadata.Name.
func (a PPPType) String() string {
	if int(a) >= 65536 {
		return "UnknownPPPType"
	}

	return PPPTypeMetadata[a].Name
}

// LayerType returns PPPTypeMetadata.LayerType.
func (a PPPType) LayerType() gopacket.LayerType {
	if int(a) >= 65536 {
		return 0
	}

	return PPPTypeMetadata[a].LayerType
}

type errorDecoderForPPPType int

func (a *errorDecoderForPPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForPPPType) Error() string {
	return fmt.Sprintf("Unable to decode PPPType %d", int(*a))
}

var (
	errorDecodersForPPPType [65536]errorDecoderForPPPType
	PPPTypeMetadata         [65536]EnumMetadata
)

func initUnknownTypesForPPPType() {
	for i := 0; i < 65536; i++ {
		errorDecodersForPPPType[i] = errorDecoderForPPPType(i)
		PPPTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForPPPType[i],
			Name:       "UnknownPPPType",
		}
	}
}

// Decoder calls IPProtocolMetadata.DecodeWith's decoder.
func (a IPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 256 {
		errDecoder := errorDecoderForIPProtocol(a)
		return &errDecoder
	}

	return IPProtocolMetadata[a].DecodeWith.Decode(data, p)
}

// String returns IPProtocolMetadata.Name.
func (a IPProtocol) String() string {
	if int(a) >= 256 {
		return "UnknownIPProtocol"
	}

	return IPProtocolMetadata[a].Name
}

// LayerType returns IPProtocolMetadata.LayerType.
func (a IPProtocol) LayerType() gopacket.LayerType {
	if int(a) >= 256 {
		return 0
	}

	return IPProtocolMetadata[a].LayerType
}

type errorDecoderForIPProtocol int

func (a *errorDecoderForIPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForIPProtocol) Error() string {
	return fmt.Sprintf("Unable to decode IPProtocol %d", int(*a))
}

var (
	errorDecodersForIPProtocol [256]errorDecoderForIPProtocol
	IPProtocolMetadata         [256]EnumMetadata
)

func initUnknownTypesForIPProtocol() {
	for i := 0; i < 256; i++ {
		errorDecodersForIPProtocol[i] = errorDecoderForIPProtocol(i)
		IPProtocolMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForIPProtocol[i],
			Name:       "UnknownIPProtocol",
		}
	}
}

// Decoder calls SCTPChunkTypeMetadata.DecodeWith's decoder.
func (a SCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 256 {
		errDecoder := errorDecoderForSCTPChunkType(a)
		return &errDecoder
	}

	return SCTPChunkTypeMetadata[a].DecodeWith.Decode(data, p)
}

// String returns SCTPChunkTypeMetadata.Name.
func (a SCTPChunkType) String() string {
	if int(a) >= 256 {
		return "UnknownSCTPChunkType"
	}

	return SCTPChunkTypeMetadata[a].Name
}

// LayerType returns SCTPChunkTypeMetadata.LayerType.
func (a SCTPChunkType) LayerType() gopacket.LayerType {
	if int(a) >= 256 {
		return 0
	}

	return SCTPChunkTypeMetadata[a].LayerType
}

type errorDecoderForSCTPChunkType int

func (a *errorDecoderForSCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForSCTPChunkType) Error() string {
	return fmt.Sprintf("Unable to decode SCTPChunkType %d", int(*a))
}

var (
	errorDecodersForSCTPChunkType [256]errorDecoderForSCTPChunkType
	SCTPChunkTypeMetadata         [256]EnumMetadata
)

func initUnknownTypesForSCTPChunkType() {
	for i := 0; i < 256; i++ {
		errorDecodersForSCTPChunkType[i] = errorDecoderForSCTPChunkType(i)
		SCTPChunkTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForSCTPChunkType[i],
			Name:       "UnknownSCTPChunkType",
		}
	}
}

// Decoder calls PPPoECodeMetadata.DecodeWith's decoder.
func (a PPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 256 {
		errDecoder := errorDecoderForPPPoECode(a)
		return &errDecoder
	}

	return PPPoECodeMetadata[a].DecodeWith.Decode(data, p)
}

// String returns PPPoECodeMetadata.Name.
func (a PPPoECode) String() string {
	if int(a) >= 256 {
		return "UnknownPPPoECode"
	}

	return PPPoECodeMetadata[a].Name
}

// LayerType returns PPPoECodeMetadata.LayerType.
func (a PPPoECode) LayerType() gopacket.LayerType {
	if int(a) >= 256 {
		return 0
	}

	return PPPoECodeMetadata[a].LayerType
}

type errorDecoderForPPPoECode int

func (a *errorDecoderForPPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForPPPoECode) Error() string {
	return fmt.Sprintf("Unable to decode PPPoECode %d", int(*a))
}

var (
	errorDecodersForPPPoECode [256]errorDecoderForPPPoECode
	PPPoECodeMetadata         [256]EnumMetadata
)

func initUnknownTypesForPPPoECode() {
	for i := 0; i < 256; i++ {
		errorDecodersForPPPoECode[i] = errorDecoderForPPPoECode(i)
		PPPoECodeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForPPPoECode[i],
			Name:       "UnknownPPPoECode",
		}
	}
}

// Decoder calls FDDIFrameControlMetadata.DecodeWith's decoder.
func (a FDDIFrameControl) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 256 {
		errDecoder := errorDecoderForFDDIFrameControl(a)
		return &errDecoder
	}

	return FDDIFrameControlMetadata[a].DecodeWith.Decode(data, p)
}

// String returns FDDIFrameControlMetadata.Name.
func (a FDDIFrameControl) String() string {
	if int(a) >= 256 {
		return "UnknownFDDIFrameControl"
	}

	return FDDIFrameControlMetadata[a].Name
}

// LayerType returns FDDIFrameControlMetadata.LayerType.
func (a FDDIFrameControl) LayerType() gopacket.LayerType {
	if int(a) >= 256 {
		return 0
	}

	return FDDIFrameControlMetadata[a].LayerType
}

type errorDecoderForFDDIFrameControl int

func (a *errorDecoderForFDDIFrameControl) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForFDDIFrameControl) Error() string {
	return fmt.Sprintf("Unable to decode FDDIFrameControl %d", int(*a))
}

var (
	errorDecodersForFDDIFrameControl [256]errorDecoderForFDDIFrameControl
	FDDIFrameControlMetadata         [256]EnumMetadata
)

func initUnknownTypesForFDDIFrameControl() {
	for i := 0; i < 256; i++ {
		errorDecodersForFDDIFrameControl[i] = errorDecoderForFDDIFrameControl(i)
		FDDIFrameControlMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForFDDIFrameControl[i],
			Name:       "UnknownFDDIFrameControl",
		}
	}
}

// Decoder calls EAPOLTypeMetadata.DecodeWith's decoder.
func (a EAPOLType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 256 {
		errDecoder := errorDecoderForEAPOLType(a)
		return &errDecoder
	}

	return EAPOLTypeMetadata[a].DecodeWith.Decode(data, p)
}

// String returns EAPOLTypeMetadata.Name.
func (a EAPOLType) String() string {
	if int(a) >= 256 {
		return "UnknownEAPOLType"
	}

	return EAPOLTypeMetadata[a].Name
}

// LayerType returns EAPOLTypeMetadata.LayerType.
func (a EAPOLType) LayerType() gopacket.LayerType {
	if int(a) >= 256 {
		return 0
	}

	return EAPOLTypeMetadata[a].LayerType
}

type errorDecoderForEAPOLType int

func (a *errorDecoderForEAPOLType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForEAPOLType) Error() string {
	return fmt.Sprintf("Unable to decode EAPOLType %d", int(*a))
}

var (
	errorDecodersForEAPOLType [256]errorDecoderForEAPOLType
	EAPOLTypeMetadata         [256]EnumMetadata
)

func initUnknownTypesForEAPOLType() {
	for i := 0; i < 256; i++ {
		errorDecodersForEAPOLType[i] = errorDecoderForEAPOLType(i)
		EAPOLTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForEAPOLType[i],
			Name:       "UnknownEAPOLType",
		}
	}
}

// Decoder calls ProtocolFamilyMetadata.DecodeWith's decoder.
func (a ProtocolFamily) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 256 {
		errDecoder := errorDecoderForProtocolFamily(a)
		return &errDecoder
	}

	return ProtocolFamilyMetadata[a].DecodeWith.Decode(data, p)
}

// String returns ProtocolFamilyMetadata.Name.
func (a ProtocolFamily) String() string {
	if int(a) >= 256 {
		return "UnknownProtocolFamily"
	}

	return ProtocolFamilyMetadata[a].Name
}

// LayerType returns ProtocolFamilyMetadata.LayerType.
func (a ProtocolFamily) LayerType() gopacket.LayerType {
	if int(a) >= 256 {
		return 0
	}

	return ProtocolFamilyMetadata[a].LayerType
}

type errorDecoderForProtocolFamily int

func (a *errorDecoderForProtocolFamily) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForProtocolFamily) Error() string {
	return fmt.Sprintf("Unable to decode ProtocolFamily %d", int(*a))
}

var (
	errorDecodersForProtocolFamily [256]errorDecoderForProtocolFamily
	ProtocolFamilyMetadata         [256]EnumMetadata
)

func initUnknownTypesForProtocolFamily() {
	for i := 0; i < 256; i++ {
		errorDecodersForProtocolFamily[i] = errorDecoderForProtocolFamily(i)
		ProtocolFamilyMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForProtocolFamily[i],
			Name:       "UnknownProtocolFamily",
		}
	}
}

// Decoder calls Dot11TypeMetadata.DecodeWith's decoder.
func (a Dot11Type) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 256 {
		errDecoder := errorDecoderForDot11Type(a)
		return &errDecoder
	}

	return Dot11TypeMetadata[a].DecodeWith.Decode(data, p)
}

// String returns Dot11TypeMetadata.Name.
func (a Dot11Type) String() string {
	if int(a) >= 256 {
		return "UnknownDot11Type"
	}

	return Dot11TypeMetadata[a].Name
}

// LayerType returns Dot11TypeMetadata.LayerType.
func (a Dot11Type) LayerType() gopacket.LayerType {
	if int(a) >= 256 {
		return 0
	}

	return Dot11TypeMetadata[a].LayerType
}

type errorDecoderForDot11Type int

func (a *errorDecoderForDot11Type) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForDot11Type) Error() string {
	return fmt.Sprintf("Unable to decode Dot11Type %d", int(*a))
}

var (
	errorDecodersForDot11Type [256]errorDecoderForDot11Type
	Dot11TypeMetadata         [256]EnumMetadata
)

func initUnknownTypesForDot11Type() {
	for i := 0; i < 256; i++ {
		errorDecodersForDot11Type[i] = errorDecoderForDot11Type(i)
		Dot11TypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForDot11Type[i],
			Name:       "UnknownDot11Type",
		}
	}
}

// Decoder calls USBTransportTypeMetadata.DecodeWith's decoder.
func (a USBTransportType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if int(a) >= 256 {
		errDecoder := errorDecoderForUSBTransportType(a)
		return &errDecoder
	}

	return USBTransportTypeMetadata[a].DecodeWith.Decode(data, p)
}

// String returns USBTransportTypeMetadata.Name.
func (a USBTransportType) String() string {
	if int(a) >= 256 {
		return "UnknownUSBTransportType"
	}

	return USBTransportTypeMetadata[a].Name
}

// LayerType returns USBTransportTypeMetadata.LayerType.
func (a USBTransportType) LayerType() gopacket.LayerType {
	if int(a) >= 256 {
		return 0
	}

	return USBTransportTypeMetadata[a].LayerType
}

type errorDecoderForUSBTransportType int

func (a *errorDecoderForUSBTransportType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return a
}

func (a *errorDecoderForUSBTransportType) Error() string {
	return fmt.Sprintf("Unable to decode USBTransportType %d", int(*a))
}

var (
	errorDecodersForUSBTransportType [256]errorDecoderForUSBTransportType
	USBTransportTypeMetadata         [256]EnumMetadata
)

func initUnknownTypesForUSBTransportType() {
	for i := 0; i < 256; i++ {
		errorDecodersForUSBTransportType[i] = errorDecoderForUSBTransportType(i)
		USBTransportTypeMetadata[i] = EnumMetadata{
			DecodeWith: &errorDecodersForUSBTransportType[i],
			Name:       "UnknownUSBTransportType",
		}
	}
}
