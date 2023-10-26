// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package add_path

import (
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	otg "github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
	"golang.org/x/exp/slices"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

const (
	ipv4PrefixLen = 30 // ipv4PrefixLen is the ATE and DUT interface IP prefix length.
	ipv6PrefixLen = 126
	ebgpDutAS1    = uint32(101)
	ebgpAteAS1    = uint32(100)
	ebgpDutAS2    = uint32(201)
	ebgpAteAS2    = uint32(200)
	globalAS      = uint32(300)

	connInternal = "INTERNAL"
)

var (
	dutEbgp1 = attrs.Attributes{
		Desc:    "dutEbgp1",
		IPv4:    "192.0.2.1",
		IPv4Len: 26,
		IPv6:    "2001:db8::192:0:2:1",
		IPv6Len: 122,
	}

	ateEbgp1 = attrs.Attributes{
		Name:    "ateEbgp1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv4Len: 26,
		IPv6:    "2001:db8::192:0:2:2",
		IPv6Len: 122,
	}

	dutEbgp2 = attrs.Attributes{
		Desc:    "dutEbgp2",
		IPv4:    "192.0.2.65",
		IPv4Len: 26,
		IPv6:    "2001:db8::192:0:2:41",
		IPv6Len: 122,
	}

	ateEbgp2 = attrs.Attributes{
		Name:    "ateEbgp2",
		MAC:     "02:00:01:01:02:01",
		IPv4:    "192.0.2.66",
		IPv4Len: 26,
		IPv6:    "2001:db8::192:0:2:42",
		IPv6Len: 122,
	}

	dutIbgp1 = attrs.Attributes{
		Desc:    "dutEbgp1",
		IPv4:    "198.51.100.1",
		IPv4Len: 25,
		IPv6:    "2001:db8::192:51:100:1",
		IPv6Len: 122,
	}

	ateIbgp1 = attrs.Attributes{
		Name:    "ateIbgp1",
		MAC:     "02:00:01:01:03:01",
		IPv4:    "198.51.100.2",
		IPv4Len: 25,
		IPv6:    "2001:db8::192:51:100:2",
		IPv6Len: 122,
	}

	dutIbgp2 = attrs.Attributes{
		Desc:    "dutIbgp2",
		IPv4:    "198.51.100.129",
		IPv4Len: 25,
		IPv6:    "2001:db8::192:51:100:41",
		IPv6Len: 122,
	}

	ateIbgp2 = attrs.Attributes{
		Name:    "ateIbgp2",
		MAC:     "02:00:01:01:04:01",
		IPv4:    "198.51.100.130",
		IPv4Len: 25,
		IPv6:    "2001:db8::192:51:100:42",
		IPv6Len: 122,
	}

	dutIbgp3 = attrs.Attributes{
		Desc:    "dutIbgp3",
		IPv4:    "192.0.2.129",
		IPv4Len: 26,
		IPv6:    "2001:db8::192:0:2:81",
		IPv6Len: 122,
	}

	ateIbgp3 = attrs.Attributes{
		Name:    "ateIbgp3",
		MAC:     "02:00:01:01:05:01",
		IPv4:    "192.0.2.130",
		IPv4Len: 26,
		IPv6:    "2001:db8::192:0:2:82",
		IPv6Len: 122,
	}

	bgpOpenMessage    byte = 01 //Defined as per BGP message format
	bgpCapability     byte = 02 //Defined as per BGP message format
	bgpAddPathMessage byte = 69 //Defined as per BGP message format
	addPathSendRecv   byte = 03 //Defined as per BGP message format
	addPathRecv       byte = 01 //Defined as per BGP message format
	addPathSend       byte = 02 //Defined as per BGP message format

	advertisedRoutesv4Ebgp      = "203.0.113.4"
	advertisedRoutesv4Ibgp      = "203.0.113.8"
	advertisedRoutesv6          = "2001:db8::203:0:113:8"
	advertisedRoutesv4PrefixLen = 32
	advertisedRoutesv6PrefixLen = 128

	nextHopCount               int
	routeCountv4, routeCountv6 uint32
	pathID                     int

	dutEbgp1Ip, dutEbgp2Ip portIpList
	dutIbgp1Ip, dutIbgp2Ip portIpList

	ateEbgp1Ip, ateEbgp2Ip portIpList
	ateIbgp1Ip, ateIbgp2Ip portIpList
)

type bgpNbr struct {
	localAS, peerAS uint32
	peerIP          string
	isV4            bool
}

type portIpList struct {
	v4, v6 []string
}

func configureDUT(t *testing.T, dut *ondatra.DUTDevice, port4Ebgp bool) {
	t.Helper()

	t.Log("Configure Network Instance")
	dutConfNIPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	gnmi.Replace(t, dut, dutConfNIPath.Type().Config(), oc.NetworkInstanceTypes_NETWORK_INSTANCE_TYPE_DEFAULT_INSTANCE)

	dp1 := dut.Port(t, "port1")
	dp2 := dut.Port(t, "port2")
	dp3 := dut.Port(t, "port3")
	dp4 := dut.Port(t, "port4")
	d := &oc.Root{}

	// configure Ethernet interfaces first
	configureInterfaceDUT(t, d, dut, dp1, dutEbgp1.Desc)
	configureInterfaceDUT(t, d, dut, dp2, dutIbgp1.Desc)
	configureInterfaceDUT(t, d, dut, dp3, dutIbgp2.Desc)
	if port4Ebgp {
		configureInterfaceDUT(t, d, dut, dp4, dutEbgp2.Desc)
	} else {
		configureInterfaceDUT(t, d, dut, dp4, dutIbgp3.Desc)
	}

	// configure an L3 subinterface without vlan tagging under DUT port 5
	createSubifDUT(t, d, dut, dp1, 0, 0, dutEbgp1)
	createSubifDUT(t, d, dut, dp2, 0, 0, dutIbgp1)
	createSubifDUT(t, d, dut, dp3, 0, 0, dutIbgp2)
	if port4Ebgp {
		createSubifDUT(t, d, dut, dp4, 0, 0, dutEbgp2)
	} else {
		createSubifDUT(t, d, dut, dp4, 0, 0, dutIbgp3)
	}

	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		fptest.AssignToNetworkInstance(t, dut, dp1.Name(), deviations.DefaultNetworkInstance(dut), 0)
	}

	gnmi.Replace(t, dut, gnmi.OC().Config(), d)

	configureBGPNeighbors(t, dut, port4Ebgp)
}

// createSubifDUT creates a single L3 subinterface
func createSubifDUT(t *testing.T, d *oc.Root, dut *ondatra.DUTDevice, dutPort *ondatra.Port, index uint32, vlanID uint16, dutAttr attrs.Attributes) {

	i := d.GetOrCreateInterface(dutPort.Name())
	s := i.GetOrCreateSubinterface(index)
	if vlanID != 0 {
		if deviations.DeprecatedVlanID(dut) {
			s.GetOrCreateVlan().VlanId = oc.UnionUint16(vlanID)
		} else {
			s.GetOrCreateVlan().GetOrCreateMatch().GetOrCreateSingleTagged().VlanId = ygot.Uint16(vlanID)
		}
	}
	s4 := s.GetOrCreateIpv4()
	v4 := s4.GetOrCreateAddress(dutAttr.IPv4)
	v4.PrefixLength = ygot.Uint8(dutAttr.IPv4Len)

	s6 := s.GetOrCreateIpv6()
	v6 := s6.GetOrCreateAddress(dutAttr.IPv6)
	v6.PrefixLength = ygot.Uint8(dutAttr.IPv6Len)

	if deviations.InterfaceEnabled(dut) && !deviations.IPv4MissingEnabled(dut) {
		s4.Enabled = ygot.Bool(true)
	}
}

func configureBGPNeighbors(t *testing.T, dut *ondatra.DUTDevice, port4Ebgp bool) {

	dutConfPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	d := &oc.Root{}
	ni1 := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	ni_proto := ni1.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	bgp := ni_proto.GetOrCreateBgp()

	global := bgp.GetOrCreateGlobal()
	global.As = ygot.Uint32(globalAS)
	global.RouterId = ygot.String(dutEbgp1.IPv4)

	rrCluster, rrClient, isExternal, configureAddPath := true, true, true, true

	createBgpNeighbor(&bgpNbr{localAS: ebgpDutAS1, peerIP: ateEbgp1.IPv4, peerAS: ebgpAteAS1, isV4: true},
		dut, bgp, "ebgp1", !rrCluster, !rrClient, isExternal, configureAddPath)

	if port4Ebgp {
		createBgpNeighbor(&bgpNbr{localAS: ebgpDutAS2, peerIP: ateEbgp2.IPv4, peerAS: ebgpAteAS2, isV4: true},
			dut, bgp, "ebgp2", !rrCluster, !rrClient, isExternal, configureAddPath)
	} else {
		nbrInfo := &bgpNbr{localAS: globalAS, peerIP: ateIbgp3.IPv4, peerAS: globalAS, isV4: true}
		createBgpNeighbor(nbrInfo, dut, bgp, "rr2", rrCluster, !rrClient, !isExternal, !configureAddPath)
	}

	createBgpNeighbor(&bgpNbr{localAS: globalAS, peerIP: ateIbgp1.IPv4, peerAS: globalAS, isV4: true},
		dut, bgp, "rr1", !rrCluster, rrClient, !isExternal, configureAddPath)

	createBgpNeighbor(&bgpNbr{localAS: globalAS, peerIP: ateIbgp2.IPv4, peerAS: globalAS, isV4: true},
		dut, bgp, "rr1", !rrCluster, rrClient, !isExternal, configureAddPath)

	t.Log("Configure BGP on DUT")
	gnmi.Replace(t, dut, dutConfPath.Config(), ni_proto)
}

func createBgpNeighbor(nbr *bgpNbr, dut *ondatra.DUTDevice, bgp *oc.NetworkInstance_Protocol_Bgp, peerGroup string,
	rrCluster, rrClient, isExternal, configureAddPath bool) {

	pg := bgp.GetOrCreatePeerGroup(peerGroup)
	pg.PeerAs = ygot.Uint32(nbr.peerAS)
	pg.PeerGroupName = ygot.String(peerGroup)

	neighbor := bgp.GetOrCreateNeighbor(nbr.peerIP)
	neighbor.PeerAs = ygot.Uint32(nbr.peerAS)
	neighbor.LocalAs = ygot.Uint32(nbr.localAS)
	neighbor.Enabled = ygot.Bool(true)
	neighbor.PeerGroup = ygot.String(peerGroup)

	if rrCluster == true {
		routeReflector := neighbor.GetOrCreateRouteReflector()
		clusterIDUnion, _ := routeReflector.To_NetworkInstance_Protocol_Bgp_Neighbor_RouteReflector_RouteReflectorClusterId_Union("2.2.2.2")
		routeReflector.SetRouteReflectorClusterId(clusterIDUnion)
	}

	if rrClient == true {
		reflectorClient := neighbor.GetOrCreateRouteReflector()
		reflectorClient.SetRouteReflectorClient(rrClient)
	}

	mpNeighbor := neighbor.GetOrCreateUseMultiplePaths()
	mpNeighbor.SetEnabled(true)
	ucmp := mpNeighbor.GetOrCreateEbgp()
	ucmp.SetAllowMultipleAs(true)

	// if isExternal {
	// 	afisafi := neighbor.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	// 	afisafi.Enabled = ygot.Bool(true)

	// 	afisafi6 := neighbor.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	// 	afisafi6.Enabled = ygot.Bool(true)

	// 	apath4 := afisafi.GetOrCreateAddPaths()
	// 	aPath6 := afisafi6.GetOrCreateAddPaths()
	// 	apath4.SetSend(false)
	// 	aPath6.SetSend(false)

	// }
	// if configureAddPath {

	// 	apath4 := afisafi.GetOrCreateAddPaths()
	// 	apath4.SetReceive(true)

	// 	if !isExternal {

	// 		apath4.SetSend(true)
	// 		apath4.SendMax = ygot.Uint8(5)
	// 	}

	// 	aPath6 := afisafi6.GetOrCreateAddPaths()
	// 	aPath6.SetReceive(true)
	// 	if !isExternal {
	// 		aPath6.SetSend(true)
	// 		aPath6.SendMax = ygot.Uint8(5)
	// 	}
	// }
}

// configureInterfaceDUT configures a single DUT port.
func configureInterfaceDUT(t *testing.T, d *oc.Root, dut *ondatra.DUTDevice, dutPort *ondatra.Port, desc string) {
	ifName := dutPort.Name()
	i := d.GetOrCreateInterface(ifName)
	i.Description = ygot.String(desc)
	i.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd
	if deviations.InterfaceEnabled(dut) {
		i.Enabled = ygot.Bool(true)
	}
	if deviations.ExplicitPortSpeed(dut) {
		i.GetOrCreateEthernet().PortSpeed = fptest.GetIfSpeed(t, dutPort)
	}
	t.Logf("DUT port %s configured", dutPort)
}

// configureOTG configures a single ATE layer 3 interface.
func configureOTG(t *testing.T, top gosnappi.Config, atePort *ondatra.Port, vlanID, localAS uint32,
	tgAttr, dutAttr attrs.Attributes, connectionType string, advertiseRoute bool) {
	t.Helper()

	dev := top.Devices().Add().SetName(tgAttr.Name)
	eth := dev.Ethernets().Add().SetName(tgAttr.Name + ".Eth").SetMac(tgAttr.MAC)
	eth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(atePort.ID())
	if vlanID != 0 {
		eth.Vlans().Add().SetName(tgAttr.Name + ".vlan").SetId(vlanID)
	}

	addrV4 := tgAttr.IPv4
	addrV6 := tgAttr.IPv6
	iDut1Ipv4 := eth.Ipv4Addresses().Add().SetName(tgAttr.Name + ".IPv4").SetAddress(addrV4).SetGateway(dutAttr.IPv4).SetPrefix(uint32(tgAttr.IPv4Len))
	eth.Ipv6Addresses().Add().SetName(tgAttr.Name + ".IPv6").SetAddress(addrV6).SetGateway(dutAttr.IPv6).SetPrefix(uint32(tgAttr.IPv6Len))

	if advertiseRoute {
		for nhIndex := 1; nhIndex < nextHopCount; nhIndex++ {
			addrV6 = incrementIPv6Address(net.ParseIP(addrV6)).String()
			eth.Ipv6Addresses().Add().SetName(tgAttr.Name + ".IPv6" + fmt.Sprint(nhIndex)).SetAddress(addrV6).SetGateway(dutAttr.IPv6).SetPrefix(uint32(tgAttr.IPv6Len))
		}
	}
	iDut1Bgp := dev.Bgp().SetRouterId(iDut1Ipv4.Address())
	iDut1Bgp4Peer := iDut1Bgp.Ipv4Interfaces().Add().SetIpv4Name(iDut1Ipv4.Name()).Peers().Add().SetName(tgAttr.Name + ".BGP4.peer")
	iDut1Bgp4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)
	iDut1Bgp4Peer.SetPeerAddress(iDut1Ipv4.Gateway()).SetAsNumber(localAS)
	if connectionType == connInternal {
		iDut1Bgp4Peer.SetAsType(gosnappi.BgpV4PeerAsType.IBGP)
	} else {
		iDut1Bgp4Peer.SetAsType(gosnappi.BgpV4PeerAsType.EBGP)
	}

	iDut1Bgp4Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut1Bgp4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)
	iDut1Bgp4Peer.LearnedInformationFilter().SetUnicastIpv6Prefix(true)

	var advAddress string
	var advAddressV6 string
	if advertiseRoute {
		if connectionType == connInternal {
			advAddress = advertisedRoutesv4Ibgp
			advAddressV6 = advertisedRoutesv6
		} else {
			advAddress = advertisedRoutesv4Ebgp
			advAddressV6 = advertisedRoutesv6
		}

		nhIp := iDut1Ipv4.Address()
		nhIp6 := tgAttr.IPv6
		pathID = 0
		for nhIndex := 0; nhIndex < nextHopCount; nhIndex++ {
			pathID++

			bgpNeti1Bgp4PeerRoutes := iDut1Bgp4Peer.V4Routes().Add().SetName(tgAttr.Name + ".BGP4.Route" + fmt.Sprint(pathID))
			bgpNeti1Bgp4PeerRoutes.Addresses().Add().
				SetAddress(advAddress).
				SetPrefix(uint32(advertisedRoutesv4PrefixLen)).SetStep(1).
				SetCount(routeCountv4)
			bgpNeti1Bgp4PeerRoutes.SetNextHopIpv4Address(nhIp).
				SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
				SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
			bgpNeti1Bgp4PeerRoutes.AddPath().SetPathId(uint32(pathID))

			nhIp = incrementIPv4Address(net.ParseIP(nhIp)).String()

			// if connectionType == connInternal {
			bgpNeti1Bgp6PeerRoutes := iDut1Bgp4Peer.V6Routes().Add().SetName(tgAttr.Name + ".BGP6.Route" + fmt.Sprint(pathID))
			bgpNeti1Bgp6PeerRoutes.Addresses().Add().
				SetAddress(advAddressV6).
				SetPrefix(uint32(advertisedRoutesv6PrefixLen)).SetStep(1).
				SetCount(routeCountv6)
			bgpNeti1Bgp6PeerRoutes.SetNextHopIpv6Address(nhIp6).
				SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6).
				SetNextHopMode(gosnappi.BgpV6RouteRangeNextHopMode.MANUAL)
			bgpNeti1Bgp6PeerRoutes.AddPath().SetPathId(uint32(pathID))

			nhIp6 = incrementIPv6Address(net.ParseIP(nhIp6)).String()
			// }
		}
	}
}

// verifyBGPSessionState checks that the dut has an established BGP session with reasonable settings.
func verifyBGPSessionState(t *testing.T, dut *ondatra.DUTDevice, nbrIPList []string, sessionState oc.E_Bgp_Neighbor_SessionState) {
	t.Helper()

	t.Logf("Verifying BGP state.")
	statePath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()
	for _, nbr := range nbrIPList {
		var status *ygnmi.Value[oc.E_Bgp_Neighbor_SessionState]
		nbrPath := statePath.Neighbor(nbr)
		t.Logf("Waiting for BGP neighbor %s to establish...", nbr)
		status, ok := gnmi.Watch(t, dut, nbrPath.SessionState().State(), 30*time.Minute, func(val *ygnmi.Value[oc.E_Bgp_Neighbor_SessionState]) bool {
			state, ok := val.Val()
			return ok && state == sessionState
		}).Await(t)
		state, _ := status.Val()
		if !ok {
			t.Fatal("No BGP neighbor formed")
		}
		t.Logf("BGP adjacency for %s: %s", nbr, state)
		if want := sessionState; state != want {
			t.Errorf("BGP peer %s status got %v, want %d", nbr, status, want)
		}
		time.Sleep(time.Duration(1) * time.Second)
	}
}

func verifyInstalledPrefixes(t *testing.T, dut *ondatra.DUTDevice, neighborIp string) {

	path := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).
		Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").
		Bgp().Neighbor(neighborIp).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Prefixes().Installed()

	op := gnmi.Get(t, dut, path.State())
	fmt.Print(op)
	fmt.Print(op)
}

func startPacketCapture(t *testing.T, top gosnappi.Config, ate *ondatra.ATEDevice, dstPort gosnappi.Port) {
	t.Helper()
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	otg.SetControlState(t, cs)
	t.Log("Start Packet Capture")
}

func savePacketCapture(t *testing.T, top gosnappi.Config, ate *ondatra.ATEDevice, dstPort gosnappi.Port) string {
	t.Helper()
	otg := ate.OTG()
	fileName := "capture.pcap"
	bytes := otg.GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(dstPort.Name()))
	f, err := os.Create(fileName)

	if err != nil {
		t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
	}
	if _, err := f.Write(bytes); err != nil {
		t.Fatalf("ERROR: Could not write bytes to pcap file: %v\n", err)
	}
	f.Close()
	t.Logf("Saved packet capture to %s", fileName)

	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.STOP)
	otg.SetControlState(t, cs)
	t.Logf("Stop Packet Capture")

	return fileName
}

func verifyAddPathCapability(t *testing.T, packet gopacket.Packet, addPathCapability byte) bool {
	t.Helper()

	bgpCapabilityOffset := 1
	addPathOffset := 2
	v4CapabilityOffset := 7
	v6CapabilityOffset := 11

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		t.Log("Application layer/Payload found.")
		bgpMarker := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		if reflect.DeepEqual(applicationLayer.LayerContents()[:16], bgpMarker) {
			t.Log("BGP packet confirmed!")
		}
		bgpMessage := applicationLayer.LayerContents()

		if bgpMessage[18] == bgpOpenMessage {
			t.Log("OPEN message detected")

			openBgpMessage := applicationLayer.LayerContents()[29:]

			for i := 0; i < len(openBgpMessage); i++ {
				//checks is open message is present (2 = 0x2)
				if openBgpMessage[i] == bgpCapability {
					// Stores the parameter length to skip
					capabilitySkipCount := int(openBgpMessage[i+bgpCapabilityOffset])

					// check if add path capability is present (69 = 0x45)
					if openBgpMessage[i+addPathOffset] == bgpAddPathMessage {
						if openBgpMessage[i+v4CapabilityOffset] == addPathCapability && openBgpMessage[i+v6CapabilityOffset] == addPathCapability {
							return true
						} else {
							t.Fatalf("Add path capability not present want - %d , got - %d",
								addPathCapability, openBgpMessage[i+v4CapabilityOffset])
							return false
						}
					} else {
						i = i + capabilitySkipCount + 1
						continue
					}
				}
			}
		}
	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		t.Fatalf("Error decoding some part of the packet: %v", err)
	}
	return false
}

func verifyPacket(t *testing.T, pcapFile string, addPathCapability byte) {
	t.Helper()

	// Open pcap file
	handle, err := pcap.OpenOffline("capture.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	var result bool
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		result = verifyAddPathCapability(t, packet, addPathCapability)
		if result {
			t.Logf("Add path capability verification successful for capability - %d", addPathCapability)
			break
		}
	}
	if result == false {
		t.Fatalf("Packet verification failed")
	}
}

// verifyPrefixesTelemetry confirms that the dut shows the correct numbers of installed, sent and
// received IPv4 prefixes
func verifyPrefixesTelemetryV4(t *testing.T, dut *ondatra.DUTDevice, wantInstalled uint32, nbrIP string) {
	t.Helper()
	statePath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()
	prefixesv4 := statePath.Neighbor(nbrIP).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Prefixes()

	if gotInstalled := gnmi.Get(t, dut, prefixesv4.Installed().State()); gotInstalled != wantInstalled {
		t.Errorf("Installed prefixes mismatch: got %v, want %v", gotInstalled, wantInstalled)
	}
}

func verifyPrefixAddPathV4(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, portName,
	bgpAdvPrefix string, expectedPathID uint32) string {
	t.Helper()
	var origin otgtelemetry.E_UnicastIpv4Prefix_Origin = 1

	_, ok := gnmi.Watch(t,
		ate.OTG(),
		gnmi.OTG().BgpPeer(portName+".BGP4.peer").UnicastIpv4Prefix(bgpAdvPrefix, 32, origin, expectedPathID).State(),
		time.Minute,
		func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv4Prefix]) bool {
			_, present := v.Val()
			return present
		}).Await(t)

	if ok {
		bgpPrefix := gnmi.Get(t, ate.OTG(), gnmi.OTG().BgpPeer(portName+".BGP4.peer").UnicastIpv4Prefix(bgpAdvPrefix, 32, origin, expectedPathID).State())
		if bgpPrefix.Address != nil && bgpPrefix.GetAddress() == bgpAdvPrefix {
			return bgpPrefix.GetNextHopIpv4Address()

		}

	}
	return ""
}

func verifyPrefixAddPathV6(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, portName,
	bgpAdvPrefix string, expectedPathID uint32) string {
	t.Helper()
	var origin otgtelemetry.E_UnicastIpv6Prefix_Origin = 1

	_, ok := gnmi.Watch(t,
		ate.OTG(),
		gnmi.OTG().BgpPeer(portName+".BGP4.peer").UnicastIpv6Prefix(bgpAdvPrefix, 128, origin, expectedPathID).State(),
		time.Minute,
		func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv6Prefix]) bool {
			_, present := v.Val()
			return present
		}).Await(t)

	if ok {
		bgpPrefix := gnmi.Get(t, ate.OTG(), gnmi.OTG().BgpPeer(portName+".BGP4.peer").UnicastIpv6Prefix(bgpAdvPrefix, 128, origin, expectedPathID).State())
		if bgpPrefix.Address != nil && bgpPrefix.GetAddress() == bgpAdvPrefix {
			return bgpPrefix.GetNextHopIpv6Address()

		}
	}
	return ""
}

func isIPv6(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() == nil
}

func verifyPrefixAddPath(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, portName string,
	bgpAdvPrefixs, expectedNextHops []string, expectedPathID []uint32) {
	t.Helper()

	var nhList []string
	var nhAddress string
	for _, bgpPrefix := range bgpAdvPrefixs {
		for _, onePathID := range expectedPathID {

			if isIPv6(bgpPrefix) {
				nhAddress = verifyPrefixAddPathV6(t, dut, ate, portName, bgpPrefix, onePathID)
				nhAddress = net.ParseIP(nhAddress).To16().String()
			} else {
				nhAddress = verifyPrefixAddPathV4(t, dut, ate, portName, bgpPrefix, onePathID)
			}
			nhList = append(nhList, nhAddress)
		}
		if compareStringLists(nhList, expectedNextHops) {
			t.Logf("Next hop verification successful for prefix %s", bgpPrefix)
		} else {
			t.Errorf("Next hop mismatch for prefix %s: got %v, want %v", bgpPrefix, nhList, expectedNextHops)
		}
		nhList = []string{}
	}
	t.Log("Verification for prefixes, nh and path ID successful")
}

func verifyPrefixAddPathScalev4(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, portName string,
	bgpAdvPrefixs, expectedNextHops []string, expectedPathID []uint32, expectedCount int) {
	t.Helper()
	// _, ok := gnmi.WatchAll(t, ate.OTG(),
	// 	gnmi.OTG().BgpPeer(portName+".BGP4.peer").UnicastIpv4PrefixAny().State(),
	// 	10*time.Minute,
	// 	func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv4Prefix]) bool {
	// 		_, present := v.Val()
	// 		return present
	// 	}).Await(t)

	var receivedPrefix []string
	pathIdMap := make(map[string][]uint32)
	nhMap := make(map[string][]string)

	ok := true
	if ok {
		bgpPrefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(portName+".BGP4.peer").UnicastIpv4PrefixAny().State())
		for _, bgpPrefix := range bgpPrefixes {
			if bgpPrefix.Address != nil && slices.Contains(bgpAdvPrefixs, bgpPrefix.GetAddress()) {

				receivedPrefix = append(receivedPrefix, bgpPrefix.GetAddress())
				pathIdMap[bgpPrefix.GetAddress()] = append(pathIdMap[bgpPrefix.GetAddress()], bgpPrefix.GetPathId())
				nhMap[bgpPrefix.GetAddress()] = append(nhMap[bgpPrefix.GetAddress()], bgpPrefix.GetNextHopIpv4Address())
			}
		}

		for _, advPrefix := range bgpAdvPrefixs {
			if !slices.Contains(receivedPrefix, advPrefix) {
				t.Fatalf("Advertised route verification failed")
			}

			if len(nhMap[advPrefix]) == expectedCount && len(pathIdMap[advPrefix]) == expectedCount {
				t.Logf("Expected number of paths received for prefix %s", advPrefix)
			} else {
				t.Fatalf("Expected number of paths not received for prefix %s want - %d", advPrefix, expectedCount)
			}

			for _, nh := range nhMap[advPrefix] {
				if !slices.Contains(expectedNextHops, nh) {
					t.Fatalf("NH verification failed for prefix %s want - %s in %v",
						advPrefix, nh, expectedNextHops)
				}
			}

			for _, id := range pathIdMap[advPrefix] {
				if !slices.Contains(expectedPathID, id) {
					t.Fatalf("Path ID verification failed for prefix %s want - %d in %v",
						advPrefix, id, expectedPathID)
				}
			}
		}
		t.Log("Verification for v4 prefixes, nh and path ID successful on OTG")
	} else {
		t.Error("Verification for v4 prefixes, nh and path ID Failed on OTG")
	}
}

// verifyPrefixesFibV4 verifies aft telemetry entries.
func verifyPrefixesFibV4(t *testing.T, dut *ondatra.DUTDevice, prefix string, nhIpAddress []string, expectedNHCount int) {
	t.Helper()

	t.Log("Verifying FIB telemetry for prefix ", prefix)
	mask := "32"

	aftPfxPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().Ipv4Entry(prefix + "/" + mask)
	aftPfxVal, found := gnmi.Watch(t, dut, aftPfxPath.State(), 20*time.Minute, func(val *ygnmi.Value[*oc.NetworkInstance_Afts_Ipv4Entry]) bool {
		value, present := val.Val()
		return present && value.GetNextHopGroup() != 0
	}).Await(t)
	if !found {
		t.Fatalf("Could not find prefix %s in telemetry AFT", prefix+"/"+mask)
	}
	t.Log("Prefix found")
	aftPfx, _ := aftPfxVal.Val()

	aftNhgPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHopGroup(aftPfx.GetNextHopGroup())

	aftNhgVal, found := gnmi.Watch(t, dut, aftNhgPath.State(), 20*time.Minute, func(val *ygnmi.Value[*oc.NetworkInstance_Afts_NextHopGroup]) bool {
		value, present := val.Val()
		return present && len(value.NextHop) == expectedNHCount
	}).Await(t)
	aftNhg, _ := aftNhgVal.Val()
	if !found {
		t.Fatalf("NHG %d next-hop entry count: got %d, want %d", aftPfx.GetNextHopGroup(), len(aftNhg.NextHop), expectedNHCount)
	}
	t.Log("NHG found")

	// aftNHG = gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHopGroup(aftPfx.GetNextHopGroup()).State())
	// if got := len(aftNHG.NextHop); got != expectedNHCount {
	// 	t.Fatalf("Prefix %s next-hop entry count: got %d, want %d", prefix+"/"+mask, got, expectedNHCount)
	// }

	// for k := range aftNhg.NextHop {
	// 	aftnh := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHop(k).State())

	// 	if got := aftnh.GetIpAddress(); !slices.Contains(nhIpAddress, got) {
	// 		t.Fatalf("Prefix %s next-hop IP: want %s in %v", prefix+"/"+mask, got, nhIpAddress)
	// 	}
	// }

	for k := range aftNhg.NextHop {
		aftNhPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHop(k)

		_, found := gnmi.Watch(t, dut, aftNhPath.State(), 20*time.Minute, func(val *ygnmi.Value[*oc.NetworkInstance_Afts_NextHop]) bool {
			value, present := val.Val()
			return present && slices.Contains(nhIpAddress, value.GetIpAddress())
		}).Await(t)
		if !found {
			t.Fatalf("Nexthop IP not found for prefix %s", prefix+"/"+mask)
		}

	}
	t.Logf("Verified FIB for prefix %s successfully", prefix+"/"+mask)
}

// verifyPrefixesFibV4 verifies aft telemetry entries.
func verifyPrefixesFibV6(t *testing.T, dut *ondatra.DUTDevice, prefix string, nhIpAddress []string, expectedNHCount int) {
	t.Helper()

	t.Log("Verifying FIB telemetry for prefix ", prefix)
	mask := "128"

	aftPfxPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().Ipv6Entry(prefix + "/" + mask)
	aftPfxVal, found := gnmi.Watch(t, dut, aftPfxPath.State(), 20*time.Minute, func(val *ygnmi.Value[*oc.NetworkInstance_Afts_Ipv6Entry]) bool {
		value, present := val.Val()
		return present && value.GetNextHopGroup() != 0
	}).Await(t)
	if !found {
		t.Fatalf("Could not find prefix %s in telemetry AFT", prefix+"/"+mask)
	}
	t.Log("Prefix found")
	aftPfx, _ := aftPfxVal.Val()

	aftNhgPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHopGroup(aftPfx.GetNextHopGroup())
	aftNhgVal, found := gnmi.Watch(t, dut, aftNhgPath.State(), 20*time.Minute, func(val *ygnmi.Value[*oc.NetworkInstance_Afts_NextHopGroup]) bool {
		value, present := val.Val()
		return present && len(value.NextHop) == expectedNHCount
	}).Await(t)
	aftNhg, _ := aftNhgVal.Val()
	if !found {
		t.Fatalf("NHG %d next-hop entry count: got %d, want %d", aftPfx.GetNextHopGroup(), len(aftNhg.NextHop), expectedNHCount)
	}
	t.Log("NHG found")

	for k := range aftNhg.NextHop {
		aftNhPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHop(k)

		_, found := gnmi.Watch(t, dut, aftNhPath.State(), 20*time.Minute, func(val *ygnmi.Value[*oc.NetworkInstance_Afts_NextHop]) bool {
			value, present := val.Val()
			return present && slices.Contains(nhIpAddress, value.GetIpAddress())
		}).Await(t)
		if !found {
			t.Fatalf("Nexthop IP not found for prefix %s", prefix+"/"+mask)
		}

	}
	t.Logf("Verified FIB for prefix %s successfully", prefix+"/"+mask)
}

// verifyPrefixesFibV4 verifies aft telemetry entries.
func verifyPrefixesFibV62(t *testing.T, dut *ondatra.DUTDevice, prefix string, nhIpAddress []string, expectedNHCount int) {
	t.Helper()

	t.Log("Verifying FIB telemetry for prefix ", prefix)
	mask := "128"

	aftPfxPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().Ipv6Entry(prefix + "/" + mask)
	aftPfxVal, found := gnmi.Watch(t, dut, aftPfxPath.State(), 10*time.Minute, func(val *ygnmi.Value[*oc.NetworkInstance_Afts_Ipv6Entry]) bool {
		value, present := val.Val()
		return present && value.GetNextHopGroup() != 0
	}).Await(t)
	if !found {
		t.Fatalf("Could not find prefix %s in telemetry AFT", prefix+"/"+mask)
	}
	aftPfx, _ := aftPfxVal.Val()

	aftNHG := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHopGroup(aftPfx.GetNextHopGroup()).State())
	if got := len(aftNHG.NextHop); got != expectedNHCount {
		t.Fatalf("Prefix %s next-hop entry count: got %d, want %d", prefix+"/"+mask, got, expectedNHCount)
	}

	for k := range aftNHG.NextHop {
		aftnh := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHop(k).State())

		if got := aftnh.GetIpAddress(); !slices.Contains(nhIpAddress, got) {
			t.Fatalf("Prefix %s next-hop IP: want %s in %v", prefix+"/"+mask, got, nhIpAddress)
		}
	}
}

func verifyPrefixesFib(t *testing.T, dut *ondatra.DUTDevice, prefix string) {
	// Build the GNMI Get request
	path := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().Ipv4EntryAny().State()
	abc := dut.GNMIOpts().GNMIOpts()
	abc.WithYGNMIOpts()
	// Send the GNMI Get request and wait for the response
	resp := gnmi.GetAll(t, dut, path)

	fmt.Print(resp)

	path2 := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHopGroupAny().State()

	// Send the GNMI Get request and wait for the response
	resp2 := gnmi.GetAll(t, dut, path2)

	fmt.Print(resp2)

	path3 := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHopAny().State()

	// Send the GNMI Get request and wait for the response
	resp3 := gnmi.GetAll(t, dut, path3)

	fmt.Print(resp3)

	pre := prefix + "/32"
	path4 := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().Ipv4Entry(pre).State()

	// Send the GNMI Get request and wait for the response
	resp4 := gnmi.Get(t, dut, path4)

	fmt.Print(resp4)
	a := resp4.GetNextHopGroup()

	path5 := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHopGroup(a).State()

	// Send the GNMI Get request and wait for the response
	resp5 := gnmi.Get(t, dut, path5)
	fmt.Print(resp5)

	b := resp5.GetNextHop(0)
	c := b.GetIndex()
	path6 := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHop(c).State()

	// Send the GNMI Get request and wait for the response
	resp6 := gnmi.Get(t, dut, path6)
	fmt.Print(resp6)

}

func configureMaxPaths(t *testing.T, b *gnmi.SetBatch, dut *ondatra.DUTDevice, configType, nbrAddress, peerGroup string, sendMax uint8) {

	t.Helper()

	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()

	switch configType {
	case "global":
		t.Logf("Configuring global max path to %v", sendMax)

		configPath4 := bgpPath.Global().AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().SendMax().Config()
		gnmi.BatchReplace(b, configPath4, sendMax)
		configPath6 := bgpPath.Global().AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().SendMax().Config()
		gnmi.BatchReplace(b, configPath6, sendMax)

	case "neighbor":
		t.Logf("Configuring neighbor max path to %v", sendMax)

		configPath4 := bgpPath.Neighbor(nbrAddress).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().SendMax().Config()
		gnmi.BatchReplace(b, configPath4, sendMax)
		configPath6 := bgpPath.Neighbor(nbrAddress).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().SendMax().Config()
		gnmi.BatchReplace(b, configPath6, sendMax)

	case "peerGroup":
		t.Logf("Configuring peerGroup max path to %v", sendMax)

		configPath4 := bgpPath.PeerGroup(peerGroup).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().SendMax().Config()
		gnmi.BatchReplace(b, configPath4, sendMax)
		configPath6 := bgpPath.PeerGroup(peerGroup).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().SendMax().Config()
		gnmi.BatchReplace(b, configPath6, sendMax)

	default:
		t.Errorf("Invalid config type!")
	}
}

func configureAddPathReceive(t *testing.T, b *gnmi.SetBatch, dut *ondatra.DUTDevice, configType, nbrAddress, peerGroup string, receive bool) {

	t.Helper()

	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()

	switch configType {
	case "global":
		t.Logf("Configuring global receive capability to %v", receive)

		configPath4 := bgpPath.Global().AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().Receive().Config()
		gnmi.BatchReplace(b, configPath4, receive)
		configPath6 := bgpPath.Global().AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().Receive().Config()
		gnmi.BatchReplace(b, configPath6, receive)

	case "neighbor":
		t.Logf("Configuring neighbor receive capability to %v", receive)

		configPath4 := bgpPath.Neighbor(nbrAddress).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().Receive().Config()
		gnmi.BatchReplace(b, configPath4, receive)
		configPath6 := bgpPath.Neighbor(nbrAddress).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().Receive().Config()
		gnmi.BatchReplace(b, configPath6, receive)

	case "peerGroup":
		t.Logf("Configuring peerGroup receive capability to %v", receive)

		configPath4 := bgpPath.PeerGroup(peerGroup).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().Receive().Config()
		gnmi.BatchReplace(b, configPath4, receive)
		configPath6 := bgpPath.PeerGroup(peerGroup).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().Receive().Config()
		gnmi.BatchReplace(b, configPath6, receive)

	default:
		t.Errorf("Invalid config type!")
	}

}

func configureAddPathSend(t *testing.T, b *gnmi.SetBatch, dut *ondatra.DUTDevice, configType, nbrAddress, peerGroup string, send bool) {

	t.Helper()

	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()

	switch configType {
	case "global":
		t.Logf("Configuring global send capability to %v", send)

		configPath4 := bgpPath.Global().AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().Send().Config()
		gnmi.BatchReplace(b, configPath4, send)
		configPath6 := bgpPath.Global().AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().Send().Config()
		gnmi.BatchReplace(b, configPath6, send)

	case "neighbor":
		t.Logf("Configuring neighbor send capability to %v", send)

		configPath4 := bgpPath.Neighbor(nbrAddress).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().Send().Config()
		gnmi.BatchReplace(b, configPath4, send)
		configPath6 := bgpPath.Neighbor(nbrAddress).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().Send().Config()
		gnmi.BatchReplace(b, configPath6, send)

	case "peerGroup":
		t.Logf("Configuring peerGroup send capability to %v", send)

		configPath4 := bgpPath.PeerGroup(peerGroup).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().Send().Config()
		gnmi.BatchReplace(b, configPath4, send)
		configPath6 := bgpPath.PeerGroup(peerGroup).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().Send().Config()
		gnmi.BatchReplace(b, configPath6, send)

	default:
		t.Errorf("Invalid config type!")
	}
}

func GenerateIfaceAddresses() {

	// Increment of 4 for /30 v4 and /126 v6 subnets
	incrFactor := 1

	ifaceCount := 2
	dutEbgp1Ip.v4 = append(dutEbgp1Ip.v4, generateIPv4Addresses(dutEbgp1.IPv4, ifaceCount, incrFactor)...)
	dutEbgp1Ip.v6 = append(dutEbgp1Ip.v6, generateIPv6Addresses(dutEbgp1.IPv6, ifaceCount, incrFactor)...)

	ateEbgp1Ip.v4 = append(ateEbgp1Ip.v4, generateIPv4Addresses(ateEbgp1.IPv4, ifaceCount, incrFactor)...)
	ateEbgp1Ip.v6 = append(ateEbgp1Ip.v6, generateIPv6Addresses(ateEbgp1.IPv6, ifaceCount, incrFactor)...)

	ifaceCount = 32
	dutIbgp1Ip.v4 = append(dutIbgp1Ip.v4, generateIPv4Addresses(dutIbgp1.IPv4, ifaceCount, incrFactor)...)
	dutIbgp2Ip.v4 = append(dutIbgp2Ip.v4, generateIPv4Addresses(dutIbgp2.IPv4, ifaceCount, incrFactor)...)
	dutIbgp1Ip.v6 = append(dutIbgp1Ip.v6, generateIPv6Addresses(dutIbgp1.IPv6, ifaceCount, incrFactor)...)
	dutIbgp2Ip.v6 = append(dutIbgp2Ip.v6, generateIPv6Addresses(dutIbgp2.IPv6, ifaceCount, incrFactor)...)

	ateIbgp1Ip.v4 = append(ateIbgp1Ip.v4, generateIPv4Addresses(ateIbgp1.IPv4, ifaceCount, incrFactor)...)
	ateIbgp2Ip.v4 = append(ateIbgp2Ip.v4, generateIPv4Addresses(ateIbgp2.IPv4, ifaceCount, incrFactor)...)
	ateIbgp1Ip.v6 = append(ateIbgp1Ip.v6, generateIPv6Addresses(ateIbgp1.IPv6, ifaceCount, incrFactor)...)
	ateIbgp2Ip.v6 = append(ateIbgp2Ip.v6, generateIPv6Addresses(ateIbgp2.IPv6, ifaceCount, incrFactor)...)
}

// bgpClearConfig removes all BGP configuration from the DUT.
func bgpClearConfig(t *testing.T, dut *ondatra.DUTDevice) {
	resetBatch := &gnmi.SetBatch{}
	gnmi.BatchDelete(resetBatch, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Config())

	if deviations.NetworkInstanceTableDeletionRequired(dut) {
		tablePath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableAny()
		for _, table := range gnmi.LookupAll(t, dut, tablePath.Config()) {
			if val, ok := table.Val(); ok {
				if val.GetProtocol() == oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP {
					gnmi.BatchDelete(resetBatch, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Table(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, val.GetAddressFamily()).Config())
				}
			}
		}
	}
	resetBatch.Set(t, dut)
}

func compareStringLists(list1, list2 []string) bool {
	// sort both lists
	sort.Strings(list1)
	sort.Strings(list2)

	// compare the sorted lists
	return reflect.DeepEqual(list1, list2)
}

func compareUint32Lists(list1, list2 []uint32) bool {
	// sort both lists
	sort.Slice(list1, func(i, j int) bool { return list1[i] < list1[j] })
	sort.Slice(list2, func(i, j int) bool { return list2[i] < list2[j] })

	// compare the sorted lists
	return reflect.DeepEqual(list1, list2)
}

func verifyBgpPackets(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, top gosnappi.Config, atePort gosnappi.Port, bgpNbr string, capability byte) {
	t.Helper()

	// Add packet capture config for port5
	top.Captures().Clear()
	top.Captures().Add().SetName(fmt.Sprintf("bgpCapture%d", capability)).SetPortNames([]string{atePort.Name()}).SetFormat(gosnappi.CaptureFormat.PCAP)
	t.Log(top.Msg().GetCaptures())
	ate.OTG().PushConfig(t, top)

	startPacketCapture(t, top, ate, atePort)
	ate.OTG().StartProtocols(t)
	bgpNbrs := []string{bgpNbr}
	verifyBGPSessionState(t, dut, bgpNbrs, oc.Bgp_Neighbor_SessionState_ESTABLISHED)

	fileName := savePacketCapture(t, top, ate, atePort)
	verifyPacket(t, fileName, capability)

	ate.OTG().StopProtocols(t)

}

type testCase struct {
	desc           string
	bgpConfigLevel string
}

func TestAddPathSendRecv(t *testing.T) {
	t.Helper()
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")

	GenerateIfaceAddresses()

	cases := []testCase{
		// {
		// 	desc:           "Verify Test1 and Test2 with bgp configs at global level",
		// 	bgpConfigLevel: "neighbor",
		// }, {
		// 	desc:           "Verify Test1 and Test2 with bgp configs at peer level",
		// 	bgpConfigLevel: "peerGroup",
		// },
		{
			desc:           "Verify Test1 and Test2 with bgp configs at neighbor level",
			bgpConfigLevel: "neighbor",
		},
	}

	for _, tc := range cases {

		t.Run(tc.desc, func(t *testing.T) {
			// tc.testAddPath(t, dut, ate, tc.bgpConfigLevel)
			// tc.TestAddPath2(t, dut, ate, tc.bgpConfigLevel)
			tc.testAddPathScaling(t, dut, ate, tc.bgpConfigLevel)
		})
	}

}

func (tc *testCase) testAddPath(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, configType string) {
	t.Log(tc.desc)

	t.Log("Clear BGP Configs on DUT")
	bgpClearConfig(t, dut)

	top := gosnappi.NewConfig()
	top.Ports().Add().SetName(ate.Port(t, "port1").ID())
	top.Ports().Add().SetName(ate.Port(t, "port2").ID())
	top.Ports().Add().SetName(ate.Port(t, "port3").ID())
	top.Ports().Add().SetName(ate.Port(t, "port4").ID())

	atePort1 := top.Ports().Items()[0]
	atePort4 := top.Ports().Items()[3]

	ap1 := ate.Port(t, "port1")
	ap2 := ate.Port(t, "port2")
	ap3 := ate.Port(t, "port3")
	ap4 := ate.Port(t, "port4")

	port4Ebgp := false
	configureDUT(t, dut, port4Ebgp)

	routeCountv4 = *ygot.Uint32(1)
	routeCountv6 = *ygot.Uint32(1)
	advertiseRoute := true

	nextHopCount = 4
	configureOTG(t, top, ap1, 0, ebgpAteAS1, ateEbgp1, dutEbgp1, "EXTERNAL", advertiseRoute)
	nextHopCount = 2
	configureOTG(t, top, ap2, 0, globalAS, ateIbgp1, dutIbgp1, "INTERNAL", advertiseRoute)
	configureOTG(t, top, ap3, 0, globalAS, ateIbgp2, dutIbgp2, "INTERNAL", advertiseRoute)
	configureOTG(t, top, ap4, 0, globalAS, ateIbgp3, dutIbgp3, "INTERNAL", false)

	ate.OTG().PushConfig(t, top)

	maxPaths := uint8(4)

	t.Logf("Configure add path Send/Receive for Ebgp1 neighbor")
	b := &gnmi.SetBatch{}
	configureAddPathReceive(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", true)
	if dut.Vendor() == ondatra.JUNIPER {
		configureAddPathSend(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", false)
		configureMaxPaths(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", maxPaths)
	} else {
		configureAddPathSend(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", true)
		configureMaxPaths(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", maxPaths)
	}

	t.Logf("Configure add path Send/Receive for Ibgp1 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateIbgp1.IPv4, "rr1", true)
	configureAddPathSend(t, b, dut, configType, ateIbgp1.IPv4, "rr1", true)
	configureMaxPaths(t, b, dut, configType, ateIbgp1.IPv4, "rr1", maxPaths)

	t.Logf("Configure add path Send/Receive for Ibgp2 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateIbgp2.IPv4, "rr1", true)
	configureAddPathSend(t, b, dut, configType, ateIbgp2.IPv4, "rr1", true)
	configureMaxPaths(t, b, dut, configType, ateIbgp2.IPv4, "rr1", maxPaths)

	t.Log("Configure add path Send/Receive for Ibgp3 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateIbgp3.IPv4, "rr2", true)
	configureAddPathSend(t, b, dut, configType, ateIbgp3.IPv4, "rr2", true)
	configureMaxPaths(t, b, dut, configType, ateIbgp3.IPv4, "rr2", maxPaths)
	b.Set(t, dut)

	t.Log("Verify BGP packet with add path capability for Ibgp neighbor")
	verifyBgpPackets(t, dut, ate, top, atePort4, ateIbgp3.IPv4, addPathSendRecv)

	t.Log("BGP packet with add path capability for Ebgp neighbor")
	if dut.Vendor() == ondatra.JUNIPER {
		verifyBgpPackets(t, dut, ate, top, atePort1, ateEbgp1.IPv4, addPathRecv)
	} else {
		verifyBgpPackets(t, dut, ate, top, atePort1, ateEbgp1.IPv4, addPathSendRecv)
	}

	ate.OTG().StartProtocols(t)
	bgpNbrs := []string{ateEbgp1.IPv4, ateIbgp1.IPv4, ateIbgp2.IPv4, ateIbgp3.IPv4}
	verifyBGPSessionState(t, dut, bgpNbrs, oc.Bgp_Neighbor_SessionState_ESTABLISHED)

	expectedPathID := []uint32{1, 2, 3, 4}
	nextHopsv4 := []string{}
	nextHopsv4 = append(nextHopsv4, generateIPv4Addresses(ateEbgp1.IPv4, 4, 1)...)
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp1.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp2.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp3.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))

	//Verify that the DUT advertises multiple paths for prefix-2 to ATE5 with different path-ids
	nextHopsv4 = []string{ateIbgp1.IPv4, incrementIPv4Address(net.ParseIP(ateIbgp1.IPv4)).String(),
		ateIbgp2.IPv4, incrementIPv4Address(net.ParseIP(ateIbgp2.IPv4)).String()}
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp3.Name, []string{advertisedRoutesv4Ibgp}, nextHopsv4, expectedPathID, int(maxPaths))

	//Verify that ATE5 receives only 3 different paths (out of 4) w/ unique path-ids from DUT for prefix-2
	maxPaths = uint8(3)
	b = &gnmi.SetBatch{}
	configureMaxPaths(t, b, dut, configType, ateIbgp1.IPv4, "rr1", maxPaths)
	configureMaxPaths(t, b, dut, configType, ateIbgp2.IPv4, "rr1", maxPaths)
	configureMaxPaths(t, b, dut, configType, ateIbgp3.IPv4, "rr2", maxPaths)
	b.Set(t, dut)

	expectedPathID = []uint32{1, 2, 3, 4}
	nextHopsv4 = append(nextHopsv4, generateIPv4Addresses(ateEbgp1.IPv4, 4, 1)...)
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp3.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))

	nextHopsv4 = []string{ateIbgp1.IPv4, incrementIPv4Address(net.ParseIP(ateIbgp1.IPv4)).String(),
		ateIbgp2.IPv4, incrementIPv4Address(net.ParseIP(ateIbgp2.IPv4)).String()}
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp3.Name, []string{advertisedRoutesv4Ibgp}, nextHopsv4, expectedPathID, int(maxPaths))

	ate.OTG().StopProtocols(t)
}

func (tc *testCase) TestAddPath2(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, configType string) {
	t.Log(tc.desc)

	t.Log("Clear BGP Configs on DUT")
	bgpClearConfig(t, dut)

	top := gosnappi.NewConfig()
	atePort1 := top.Ports().Add().SetName(ate.Port(t, "port1").ID())
	atePort2 := top.Ports().Add().SetName(ate.Port(t, "port2").ID())
	atePort3 := top.Ports().Add().SetName(ate.Port(t, "port3").ID())
	atePort4 := top.Ports().Add().SetName(ate.Port(t, "port4").ID())

	ap1 := ate.Port(t, "port1")
	ap2 := ate.Port(t, "port2")
	ap3 := ate.Port(t, "port3")
	ap4 := ate.Port(t, "port4")

	port4Ebgp := false
	configureDUT(t, dut, port4Ebgp)

	routeCountv4 = *ygot.Uint32(1)
	routeCountv6 = *ygot.Uint32(1)
	advertiseRoute := true

	nextHopCount = 4
	configureOTG(t, top, ap1, 0, ebgpAteAS1, ateEbgp1, dutEbgp1, "EXTERNAL", advertiseRoute)
	configureOTG(t, top, ap2, 0, globalAS, ateIbgp1, dutIbgp1, "INTERNAL", false)
	configureOTG(t, top, ap3, 0, globalAS, ateIbgp2, dutIbgp2, "INTERNAL", false)
	configureOTG(t, top, ap4, 0, globalAS, ateIbgp3, dutIbgp3, "INTERNAL", false)

	ate.OTG().PushConfig(t, top)

	maxPaths := uint8(4)
	b := &gnmi.SetBatch{}

	t.Logf("Configure add path Send/Receive for Ebgp1 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", true)
	if dut.Vendor() == ondatra.JUNIPER {
		configureAddPathSend(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", false)
		configureMaxPaths(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", maxPaths)
	} else {
		configureAddPathSend(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", true)
		configureMaxPaths(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", maxPaths)
	}

	t.Logf("Configure add path Send for Ibgp1 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateIbgp1.IPv4, "rr1", false)
	configureAddPathSend(t, b, dut, configType, ateIbgp1.IPv4, "rr1", true)
	configureMaxPaths(t, b, dut, configType, ateIbgp1.IPv4, "rr1", maxPaths)

	t.Logf("Configure add path Send for Ibgp2 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateIbgp2.IPv4, "rr1", false)
	configureAddPathSend(t, b, dut, configType, ateIbgp2.IPv4, "rr1", true)
	configureMaxPaths(t, b, dut, configType, ateIbgp2.IPv4, "rr1", maxPaths)

	t.Log("Configure add path Send/Receive for Ibgp3 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateIbgp3.IPv4, "rr2", false)
	configureAddPathSend(t, b, dut, configType, ateIbgp3.IPv4, "rr2", true)
	configureMaxPaths(t, b, dut, configType, ateIbgp3.IPv4, "rr2", maxPaths)
	b.Set(t, dut)

	t.Log("BGP packet with add path capability for Ebgp neighbor")
	verifyBgpPackets(t, dut, ate, top, atePort1, ateEbgp1.IPv4, addPathRecv)

	t.Log("Verify BGP packet with add path capability for Ibgp1 neighbor")
	verifyBgpPackets(t, dut, ate, top, atePort2, ateIbgp1.IPv4, addPathSend)

	t.Log("Verify BGP packet with add path capability for Ibgp2 neighbor")
	verifyBgpPackets(t, dut, ate, top, atePort3, ateIbgp2.IPv4, addPathSend)

	t.Log("Verify BGP packet with add path capability for Ibgp3 neighbor")
	verifyBgpPackets(t, dut, ate, top, atePort4, ateIbgp3.IPv4, addPathSend)

	ate.OTG().StartProtocols(t)
	bgpNbrs := []string{ateEbgp1.IPv4, ateIbgp1.IPv4, ateIbgp2.IPv4, ateIbgp3.IPv4}
	verifyBGPSessionState(t, dut, bgpNbrs, oc.Bgp_Neighbor_SessionState_ESTABLISHED)

	// Verify that the DUT is advertising multiple paths to prefix-1 to RRCs ATE3 and ATE4
	// as well as to the RRS ATE5 with different path-ids
	expectedPathID := []uint32{1, 2, 3, 4}
	nextHopsv4 := []string{}
	nextHopsv4 = append(nextHopsv4, generateIPv4Addresses(ateEbgp1.IPv4, 4, 1)...)

	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp1.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp2.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp3.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))

	t.Log("Verify that ATE5 receives only 3 different paths (out of 4) w/ unique path-ids from DUT for prefix-2")
	maxPaths = uint8(3)
	b = &gnmi.SetBatch{}
	configureMaxPaths(t, b, dut, configType, ateIbgp1.IPv4, "rr1", maxPaths)
	configureMaxPaths(t, b, dut, configType, ateIbgp2.IPv4, "rr1", maxPaths)
	configureMaxPaths(t, b, dut, configType, ateIbgp3.IPv4, "rr2", maxPaths)
	b.Set(t, dut)

	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp1.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp2.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))
	verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp3.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, int(maxPaths))

	ate.OTG().StopProtocols(t)
}

func (tc *testCase) testAddPathScaling(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, configType string) {
	t.Log(tc.desc)

	// otg := ate.OTG()
	t.Log("Clear BGP Configs on DUT")
	bgpClearConfig(t, dut)

	top := gosnappi.NewConfig()
	top.Ports().Add().SetName(ate.Port(t, "port1").ID())
	atePort2 := top.Ports().Add().SetName(ate.Port(t, "port2").ID())
	atePort3 := top.Ports().Add().SetName(ate.Port(t, "port3").ID())
	top.Ports().Add().SetName(ate.Port(t, "port4").ID())

	ap1 := ate.Port(t, "port1")
	ap2 := ate.Port(t, "port2")
	ap3 := ate.Port(t, "port3")
	ap4 := ate.Port(t, "port4")

	port4Ebgp := true
	configureDUT(t, dut, port4Ebgp)

	maxPaths := uint8(4)
	b := &gnmi.SetBatch{}

	configType = "neighbor"
	t.Logf("Configure add path Receive for Ebgp1 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateEbgp1.IPv4, "ebgp1", false)

	t.Logf("Configure add path Send for Ebgp2 neighbor")
	configureAddPathReceive(t, b, dut, configType, ateEbgp2.IPv4, "ebgp2", false)

	t.Logf("Configure add path Send for Ibgp1 neighbor")
	configureAddPathSend(t, b, dut, configType, ateIbgp1.IPv4, "rr1", true)
	configureMaxPaths(t, b, dut, configType, ateIbgp1.IPv4, "rr1", maxPaths)

	t.Logf("Configure add path Send for Ibgp2 neighbor")
	configureAddPathSend(t, b, dut, configType, ateIbgp2.IPv4, "rr1", true)
	configureMaxPaths(t, b, dut, configType, ateIbgp2.IPv4, "rr1", maxPaths)

	b.Set(t, dut)

	advertiseRoute := true
	routeCountv4 = *ygot.Uint32(1000000)
	routeCountv6 = *ygot.Uint32(600000)
	nextHopCount = 32

	advPrefixScalev4 := generateIPv4Addresses(advertisedRoutesv4Ebgp, int(routeCountv4), 1)
	advPrefixScalev6 := generateIPv6Addresses(advertisedRoutesv6, int(routeCountv6), 1)

	t.Logf("%s %s", atePort2.Name(), atePort3.Name())
	configureOTG(t, top, ap1, 0, ebgpAteAS1, ateEbgp1, dutEbgp1, "EXTERNAL", false)
	configureOTG(t, top, ap2, 0, globalAS, ateIbgp1, dutIbgp1, "INTERNAL", false)
	configureOTG(t, top, ap3, 0, globalAS, ateIbgp2, dutIbgp2, "INTERNAL", false)
	configureOTG(t, top, ap4, 0, ebgpAteAS2, ateEbgp2, dutEbgp2, "EXTERNAL", false)

	t.Log("Verify BGP packet with add path capability for Ibgp1 neighbor")
	verifyBgpPackets(t, dut, ate, top, atePort2, ateIbgp1.IPv4, addPathSend)

	t.Log("Verify BGP packet with add path capability for Ibgp2 neighbor")
	verifyBgpPackets(t, dut, ate, top, atePort3, ateIbgp2.IPv4, addPathSend)

	top.Captures().Clear()
	top.Devices().Clear()

	configureOTG(t, top, ap1, 0, ebgpAteAS1, ateEbgp1, dutEbgp1, "EXTERNAL", advertiseRoute)
	configureOTG(t, top, ap2, 0, globalAS, ateIbgp1, dutIbgp1, "INTERNAL", false)
	configureOTG(t, top, ap3, 0, globalAS, ateIbgp2, dutIbgp2, "INTERNAL", false)
	configureOTG(t, top, ap4, 0, ebgpAteAS2, ateEbgp2, dutEbgp2, "EXTERNAL", advertiseRoute)

	ate.OTG().PushConfig(t, top)
	ate.OTG().StartProtocols(t)

	currentTime := time.Now().Unix()
	fmt.Println(currentTime)

	bgpNbrs := []string{ateEbgp1.IPv4, ateEbgp2.IPv4, ateIbgp1.IPv4, ateIbgp2.IPv4}
	verifyBGPSessionState(t, dut, bgpNbrs, oc.Bgp_Neighbor_SessionState_ESTABLISHED)

	currentTime = time.Now().Unix()
	fmt.Println(currentTime)

	nextHopsv4 := []string{}
	nextHopsv4 = append(nextHopsv4, generateIPv4Addresses(ateEbgp1.IPv4, 32, 1)...)
	nextHopsv4 = append(nextHopsv4, generateIPv4Addresses(ateEbgp2.IPv4, 32, 1)...)

	nextHopsv6 := []string{}
	nextHopsv6 = append(nextHopsv6, generateIPv6Addresses(ateEbgp1.IPv6, 32, 1)...)
	nextHopsv6 = append(nextHopsv6, generateIPv6Addresses(ateEbgp2.IPv6, 32, 1)...)

	verifyPrefixesFibV4(t, dut, advertisedRoutesv4Ebgp, nextHopsv4, 2)
	verifyPrefixesFibV6(t, dut, advertisedRoutesv6, nextHopsv6, 2)

	currentTime = time.Now().Unix()
	fmt.Println(currentTime)

	// t.Log("Verify all prefixes are received by Ibgp neighbors on OTG")
	// totalRoutes := routeCountv4*2 + routeCountv6*2
	// verifyBGPPrefixCount(t, otg, "ateIbgp1.BGP4.peer", uint64(totalRoutes))
	// verifyBGPPrefixCount(t, otg, "ateIbgp2.BGP4.peer", uint64(totalRoutes))

	// expectedPathID := []uint32{}
	// for pathID := 1; pathID <= 64; pathID++ {
	// 	expectedPathID = append(expectedPathID, uint32(pathID))
	// }
	// verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp1.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, 2)
	// verifyPrefixAddPathScalev4(t, dut, ate, ateIbgp2.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID, 2)

	//------------------------------------

	top.Captures().Clear()
	top.Devices().Clear()

	configureOTG(t, top, ap1, 0, ebgpAteAS1, ateEbgp1, dutEbgp1, "EXTERNAL", advertiseRoute)
	configureOTG(t, top, ap2, 0, globalAS, ateIbgp1, dutIbgp1, "INTERNAL", false)
	configureOTG(t, top, ap3, 0, globalAS, ateIbgp2, dutIbgp2, "INTERNAL", false)
	routeCountv4 = routeCountv4 / 2
	routeCountv6 = routeCountv6 / 2
	configureOTG(t, top, ap4, 0, ebgpAteAS2, ateEbgp2, dutEbgp2, "EXTERNAL", advertiseRoute)

	ate.OTG().PushConfig(t, top)
	ate.OTG().StartProtocols(t)

	currentTime = time.Now().Unix()
	fmt.Println(currentTime)

	verifyBGPSessionState(t, dut, bgpNbrs, oc.Bgp_Neighbor_SessionState_ESTABLISHED)

	currentTime = time.Now().Unix()
	fmt.Println(currentTime)

	verifyPrefixesFibV4(t, dut, advertisedRoutesv4Ebgp, nextHopsv4, 2)
	verifyPrefixesFibV6(t, dut, advertisedRoutesv6, nextHopsv6, 2)
	verifyPrefixesFibV4(t, dut, advPrefixScalev4[len(advPrefixScalev4)-1], nextHopsv4, 1)
	verifyPrefixesFibV6(t, dut, advPrefixScalev6[len(advPrefixScalev6)-1], nextHopsv6, 1)

	currentTime = time.Now().Unix()
	fmt.Println(currentTime)
	// t.Log("Verify prefix count received by Ibgp neighbors on OTG")
	// totalRoutes = totalRoutes * 3
	// verifyBGPPrefixCount(t, otg, "ateIbgp1.BGP4.peer", uint64(totalRoutes))
	// verifyBGPPrefixCount(t, otg, "ateIbgp2.BGP4.peer", uint64(totalRoutes))

}

// verifies the BGP prefix count on an OTG device
func verifyBGPPrefixCount(t *testing.T, otg *otg.OTG, nbrAddress string, wantCount uint64) {
	prefixPath := gnmi.OTG().BgpPeer(nbrAddress).Counters().InRoutes().State()

	gotCount, ok := gnmi.Watch(t, otg, prefixPath, 3*time.Minute, func(v *ygnmi.Value[uint64]) bool {
		prefixCount, _ := v.Val()
		return prefixCount == wantCount
	}).Await(t)

	if !ok {
		t.Errorf("BGP prefix count mismatch: got %v, want %v", gotCount, wantCount)
	} else {
		t.Log("BGP prefix countverification successful on OTG")
	}
}

func generateIPv6Addresses(startIP string, count, incrementFactor int) []string {
	ip := net.ParseIP(startIP)
	ipv6Addresses := make([]string, count)

	for i := range ipv6Addresses {
		ipv6Addresses[i] = ip.String()
		factor := 0
		for factor < incrementFactor {
			ip = incrementIPv6Address(ip)
			factor++
		}
	}
	return ipv6Addresses
}

func incrementIPv6Address(ip net.IP) net.IP {
	ipv6Address := [16]byte{}
	copy(ipv6Address[:], ip.To16())

	for i := len(ipv6Address) - 1; i >= 0; i-- {
		ipv6Address[i]++
		if ipv6Address[i] != 0 {
			break
		}
	}
	return net.IP(ipv6Address[:])
}

func generateIPv4Addresses(startIP string, count, incrementFactor int) []string {
	ip := net.ParseIP(startIP)
	ipv4Addresses := make([]string, count)

	for i := range ipv4Addresses {
		ipv4Addresses[i] = ip.String()
		factor := 0
		for factor < incrementFactor {
			ip = incrementIPv4Address(ip)
			factor++
		}
	}
	return ipv4Addresses
}

func incrementIPv4Address(ip net.IP) net.IP {
	ipv4Address := [4]byte{}
	copy(ipv4Address[:], ip.To4())

	for i := len(ipv4Address) - 1; i >= 0; i-- {
		ipv4Address[i]++
		if ipv4Address[i] != 0 {
			break
		}
	}
	return net.IP(ipv4Address[:])
}
