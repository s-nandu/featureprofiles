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
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
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
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// Settings for configuring the baseline testbed with the test
// topology.
//
// The testbed consists of ate:port1 -> dut:port1
// and dut:port2 -> ate:port2.
// There are 64 SubInterfaces between dut:port2
// and ate:port2
//
//   - ate:port1 -> dut:port1 subnet 192.0.2.0/30
//   - ate:port2 -> dut:port2 64 Sub interfaces:
//   - ate:port2.0 -> dut:port2.0 VLAN-ID: 0 subnet 198.51.100.0/30
//   - ate:port2.1 -> dut:port2.1 VLAN-ID: 1 subnet 198.51.100.4/30
//   - ate:port2.2 -> dut:port2.2 VLAN-ID: 2 subnet 198.51.100.8/30
//   - ate:port2.i -> dut:port2.i VLAN-ID i subnet 198.51.100.(4*i)/30
//   - ate:port2.63 -> dut:port2.63 VLAN-ID 63 subnet 198.51.100.252/30
const (
	ipv4PrefixLen = 30 // ipv4PrefixLen is the ATE and DUT interface IP prefix length.
	ipv6PrefixLen = 126
	ebgpDutAS1    = uint32(70000)
	ebgpAteAS1    = uint32(70001)
	ebgpDutAS2    = uint32(80000)
	ebgpAteAS2    = uint32(80001)
	globalAS      = uint32(10000)

	flow1           = "v4FlowPort1toPort2"
	trafficDuration = 4 * time.Minute
	tolerancePct    = 2
	totalPeers      = 64
	aggregatePolicy = "aggregateBW"
	sourcePeer      = "sourceGroup"
	connInternal    = "INTERNAL"
)

var (
	dutEbgp1 = attrs.Attributes{
		Desc:    "dutEbgp1",
		IPv4:    "192.0.2.1",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:db8::192:0:2:1",
		IPv6Len: ipv6PrefixLen,
	}

	ateEbgp1 = attrs.Attributes{
		Name:    "ateEbgp1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:db8::192:0:2:2",
		IPv6Len: ipv6PrefixLen,
	}

	dutEbgp2 = attrs.Attributes{
		Desc:    "dutEbgp2",
		IPv4:    "192.0.2.9",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:db8::192:0:2:9",
		IPv6Len: ipv6PrefixLen,
	}

	ateEbgp2 = attrs.Attributes{
		Name:    "ateEbgp2",
		MAC:     "02:00:01:01:02:01",
		IPv4:    "192.0.2.10",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:db8::192:0:2:a",
		IPv6Len: ipv6PrefixLen,
	}

	dutIbgp1 = attrs.Attributes{
		Desc:    "dutEbgp1",
		IPv4:    "198.51.100.1",
		IPv4Len: 24,
		IPv6:    "2001:db8::192:51:100:1",
		IPv6Len: ipv6PrefixLen,
	}

	ateIbgp1 = attrs.Attributes{
		Name:    "ateIbgp1",
		MAC:     "02:00:01:01:03:01",
		IPv4:    "198.51.100.2",
		IPv4Len: 24,
		IPv6:    "2001:db8::192:51:100:2",
		IPv6Len: ipv6PrefixLen,
	}

	dutIbgp2 = attrs.Attributes{
		Desc:    "dutIbgp2",
		IPv4:    "198.51.100.129",
		IPv4Len: 24,
		IPv6:    "2001:db8::192:51:100:129",
		IPv6Len: ipv6PrefixLen,
	}

	ateIbgp2 = attrs.Attributes{
		Name:    "ateIbgp2",
		MAC:     "02:00:01:01:04:01",
		IPv4:    "198.51.100.130",
		IPv4Len: 24,
		IPv6:    "2001:db8::192:51:100:12a",
		IPv6Len: ipv6PrefixLen,
	}

	dutIbgp3 = attrs.Attributes{
		Desc:    "dutIbgp3",
		IPv4:    "192.0.2.17",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:db8::192:0:2:15",
		IPv6Len: ipv6PrefixLen,
	}

	ateIbgp3 = attrs.Attributes{
		Name:    "ateIbgp3",
		MAC:     "02:00:01:01:05:01",
		IPv4:    "192.0.2.18",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:db8::192:0:2:16",
		IPv6Len: ipv6PrefixLen,
	}

	bgpOpenMessage    byte = 01 //Defined as per BGP message format
	bgpCapability     byte = 02 //Defined as per BGP message format
	bgpAddPathMessage byte = 69 //Defined as per BGP message format
	addPathSendRecv   byte = 03 //Defined as per BGP message format
	addPathRecv       byte = 02 //Defined as per BGP message format

	advertisedRoutesv4Ebgp      = "203.0.113.4"
	advertisedRoutesv4Ibgp      = "203.0.113.8"
	advertisedRoutesv6Ibgp      = "2001:db8::203:0:113:8"
	advertisedRoutesv4PrefixLen = 32

	advertisedRoutesv4Scale = "198.51.100.0"

	bgpAdvIpScale              = []string{}
	dutDstIp                   = []string{}
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

func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()

	t.Log("Configure Network Instance")
	dutConfNIPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	gnmi.Replace(t, dut, dutConfNIPath.Type().Config(), oc.NetworkInstanceTypes_NETWORK_INSTANCE_TYPE_DEFAULT_INSTANCE)

	dp1 := dut.Port(t, "port1")
	dp2 := dut.Port(t, "port2")
	dp3 := dut.Port(t, "port3")
	dp4 := dut.Port(t, "port4")
	dp5 := dut.Port(t, "port5")
	d := &oc.Root{}

	// configure Ethernet interfaces first
	configureInterfaceDUT(t, d, dut, dp1, dutEbgp1.Desc)
	configureInterfaceDUT(t, d, dut, dp2, dutEbgp2.Desc)
	configureInterfaceDUT(t, d, dut, dp3, dutIbgp1.Desc)
	configureInterfaceDUT(t, d, dut, dp4, dutIbgp2.Desc)
	configureInterfaceDUT(t, d, dut, dp5, dutIbgp3.Desc)

	// configure an L3 subinterface without vlan tagging under DUT port 5
	createSubifDUT(t, d, dut, dp1, 0, 0, dutEbgp1)
	createSubifDUT(t, d, dut, dp2, 0, 0, dutEbgp2)
	createSubifDUT(t, d, dut, dp3, 0, 0, dutIbgp1)
	createSubifDUT(t, d, dut, dp4, 0, 0, dutIbgp2)
	createSubifDUT(t, d, dut, dp5, 0, 0, dutIbgp3)

	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		fptest.AssignToNetworkInstance(t, dut, dp1.Name(), deviations.DefaultNetworkInstance(dut), 0)
	}

	// configure variable L3 subinterfaces under DUT port#2 and assign them to DEFAULT vrf
	// configureDUTSubIfs(t, d, dut, dp1, 2, dutEbgp1Ip)
	// configureDUTSubIfs(t, d, dut, dp2, 2, dutEbgp2Ip)
	// configureDUTSubIfs(t, d, dut, dp3, 32, dutIbgp1Ip)
	// configureDUTSubIfs(t, d, dut, dp4, 32, dutIbgp2Ip)

	gnmi.Replace(t, dut, gnmi.OC().Config(), d)

	configureBGPNeighbors(t, dut)
}

// configureDUTSubIfs configures 64 DUT subinterfaces on the target device
func configureDUTSubIfs(t *testing.T, d *oc.Root, dut *ondatra.DUTDevice, dutPort *ondatra.Port, intfCount int, dutPortIpList portIpList) {
	t.Helper()

	for i, dutIp := range dutPortIpList.v4 {
		index := uint32(i)
		vlanID := uint16(i)
		if deviations.NoMixOfTaggedAndUntaggedSubinterfaces(dut) {
			vlanID = uint16(i) + 1
		}
		dutSubPort := attrs.Attributes{
			IPv4:    dutIp,
			IPv4Len: ipv4PrefixLen,
			IPv6:    dutPortIpList.v6[i],
			IPv6Len: ipv6PrefixLen,
		}

		createSubifDUT(t, d, dut, dutPort, index, vlanID, dutSubPort)
		if deviations.ExplicitInterfaceInDefaultVRF(dut) {
			fptest.AssignToNetworkInstance(t, dut, dutPort.Name(), deviations.DefaultNetworkInstance(dut), index)
		}
	}
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

func configureBGPNeighbors(t *testing.T, dut *ondatra.DUTDevice) {

	dutConfPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	d := &oc.Root{}
	ni1 := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	ni_proto := ni1.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	bgp := ni_proto.GetOrCreateBgp()

	global := bgp.GetOrCreateGlobal()
	global.As = ygot.Uint32(globalAS)
	global.RouterId = ygot.String(dutEbgp1.IPv4)

	rrCluster, rrClient, isExternal := true, true, true

	// configureBGPNeighborsSubIf(t, dut, bgp, "ebgp1", ebgpDutAS1, ebgpAteAS1, ateEbgp1Ip.v4, !rrCluster, !rrClient, isExternal)
	// configureBGPNeighborsSubIf(t, dut, bgp, "ebgp2", ebgpDutAS2, ebgpAteAS2, ateEbgp2Ip.v4, !rrCluster, !rrClient, isExternal)
	// configureBGPNeighborsSubIf(t, dut, bgp, "rr1", globalAS, globalAS, ateIbgp1Ip.v4, rrCluster, !rrClient, !isExternal)
	// configureBGPNeighborsSubIf(t, dut, bgp, "rr1", globalAS, globalAS, ateIbgp2Ip.v4, rrCluster, !rrClient, !isExternal)

	createBgpNeighbor(&bgpNbr{localAS: ebgpDutAS1, peerIP: ateEbgp1.IPv4, peerAS: ebgpAteAS1, isV4: true},
		dut, bgp, "ebgp1", !rrCluster, !rrClient, isExternal)

	createBgpNeighbor(&bgpNbr{localAS: ebgpDutAS2, peerIP: ateEbgp2.IPv4, peerAS: ebgpAteAS2, isV4: true},
		dut, bgp, "ebgp2", !rrCluster, !rrClient, isExternal)

	createBgpNeighbor(&bgpNbr{localAS: globalAS, peerIP: ateIbgp1.IPv4, peerAS: globalAS, isV4: true},
		dut, bgp, "rr1", rrCluster, !rrClient, !isExternal)

	createBgpNeighbor(&bgpNbr{localAS: globalAS, peerIP: ateIbgp2.IPv4, peerAS: globalAS, isV4: true},
		dut, bgp, "rr1", rrCluster, !rrClient, !isExternal)

	nbrInfo := &bgpNbr{localAS: globalAS, peerIP: ateIbgp3.IPv4, peerAS: globalAS, isV4: true}
	createBgpNeighbor(nbrInfo, dut, bgp, "rr2", !rrCluster, rrClient, !isExternal)

	t.Log("Configure BGP on DUT")
	gnmi.Replace(t, dut, dutConfPath.Config(), ni_proto)
}

func configureBGPNeighborsSubIf(t *testing.T, dut *ondatra.DUTDevice, bgp *oc.NetworkInstance_Protocol_Bgp, peerGrp string,
	localAS, peerAS uint32, peerIp []string, rrCluster, rrClient, isExternal bool) {
	t.Helper()

	for i, ateIp := range peerIp {

		if isExternal {
			localAS = localAS + uint32(i*100)
			peerAS = peerAS + uint32(i*100)
		}

		nbrInfo := &bgpNbr{localAS: localAS, peerIP: ateIp, peerAS: peerAS, isV4: true}
		createBgpNeighbor(nbrInfo, dut, bgp, peerGrp, rrCluster, rrClient, isExternal)

	}

}

func createBgpNeighbor(nbr *bgpNbr, dut *ondatra.DUTDevice, bgp *oc.NetworkInstance_Protocol_Bgp, peerGroup string,
	rrCluster, rrClient, isExternal bool) {

	pg := bgp.GetOrCreatePeerGroup(peerGroup)
	pg.PeerAs = ygot.Uint32(nbr.peerAS)
	pg.PeerGroupName = ygot.String(peerGroup)
	// mp := pg.GetOrCreateUseMultiplePaths()
	// mp.SetEnabled(true)
	// ebgp := mp.GetOrCreateEbgp()
	// ebgp.SetAllowMultipleAs(true)

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

	afisafi := neighbor.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	afisafi.Enabled = ygot.Bool(true)
	if !isExternal {
		apath4 := afisafi.GetOrCreateAddPaths()
		apath4.SetReceive(true)
		apath4.SetSend(true)
		apath4.SendMax = ygot.Uint8(5)
	}

	afisafi6 := neighbor.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	afisafi6.Enabled = ygot.Bool(true)
	if !isExternal {
		aPath6 := afisafi6.GetOrCreateAddPaths()
		aPath6.SetReceive(true)
		aPath6.SetSend(true)
		aPath6.SendMax = ygot.Uint8(5)
	}

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
	// gnmi.Replace(t, dut, gnmi.OC().Interface(ifName).Config(), i)
	t.Logf("DUT port %s configured", dutPort)
}

func nextIP(t *testing.T, ip string) string {
	t.Helper()
	// Split the IP address into four parts.
	parts := strings.Split(ip, ".")

	// Get the current IP address.
	currentIP := parts[0] + "." + parts[1] + "." + parts[2]

	lastOctet, err := strconv.Atoi(parts[3])
	if err != nil && lastOctet+2 > 255 {
		t.Errorf("Cannot convert %s\n to integer", parts[3])

	}
	// Get the next IP address.
	nextIP := currentIP + "." + strconv.Itoa(lastOctet+1)

	// Return the next IP address.
	return nextIP
}

// configureATE configures a single ATE layer 3 interface.
func configureATE(t *testing.T, top gosnappi.Config, atePort *ondatra.Port, vlanID, localAS uint32,
	tgAttr, dutAttr attrs.Attributes, connectionType string, advertiseRoute bool) {
	t.Helper()

	dev := top.Devices().Add().SetName(tgAttr.Name)
	eth := dev.Ethernets().Add().SetName(tgAttr.Name + ".Eth").SetMac(tgAttr.MAC)
	eth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(atePort.ID())
	if vlanID != 0 {
		eth.Vlans().Add().SetName(tgAttr.Name + ".vlan").SetId(vlanID)
	}
	iDut1Ipv4 := eth.Ipv4Addresses().Add().SetName(tgAttr.Name + ".IPv4").SetAddress(tgAttr.IPv4).SetGateway(dutAttr.IPv4).SetPrefix(uint32(tgAttr.IPv4Len))
	eth.Ipv6Addresses().Add().SetName(tgAttr.Name + ".IPv6").SetAddress(tgAttr.IPv6).SetGateway(dutAttr.IPv6).SetPrefix(uint32(tgAttr.IPv6Len))

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
			advAddressV6 = advertisedRoutesv6Ibgp
		} else {
			advAddress = advertisedRoutesv4Ebgp
		}
		fmt.Println(advAddressV6)
		// bgpNeti1Bgp4PeerRoutes := iDut1Bgp4Peer.V4Routes().Add().SetName(ate.Name + ".BGP4.Route")

		// bgpNeti1Bgp4PeerRoutes.Addresses().Add().
		// 	SetAddress(advAddress).
		// 	SetPrefix(uint32(advertisedRoutesv4PrefixLen)).SetStep(1).
		// 	SetCount(routeCountv4)

		// bgpNeti1Bgp4PeerRoutes.SetNextHopIpv4Address(iDut1Ipv4.Address()).
		// 	SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4).
		// 	SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
		// bgpNeti1Bgp4PeerRoutes.AddPath().SetPathId(uint32(222))

		nhIp := iDut1Ipv4.Address()
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
			// nhIp = nextIP(t, nhIp)

			// if connectionType == connInternal {

			// 	bgpNeti1Bgp6PeerRoutes := iDut1Bgp4Peer.V6Routes().Add().SetName(tgAttr.Name + ".BGP6.Route" + fmt.Sprint(pathID))
			// 	bgpNeti1Bgp6PeerRoutes.Addresses().Add().
			// 		SetAddress(advAddressV6).
			// 		SetPrefix(uint32(128)).SetStep(1).
			// 		SetCount(routeCountv6)
			// 	bgpNeti1Bgp6PeerRoutes.SetNextHopIpv6Address(tgAttr.IPv6).
			// 		SetNextHopAddressType(gosnappi.BgpV6RouteRangeNextHopAddressType.IPV6).
			// 		SetNextHopMode(gosnappi.BgpV6RouteRangeNextHopMode.MANUAL)
			// 	bgpNeti1Bgp6PeerRoutes.AddPath().SetPathId(uint32(pathID))
			// }
		}

	}
}

// incrementMAC increments the MAC by i. Returns error if the mac cannot be parsed or overflows the mac address space
func incrementMAC(mac string, i int) (string, error) {
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return "", err
	}
	convMac := binary.BigEndian.Uint64(append([]byte{0, 0}, macAddr...))
	convMac = convMac + uint64(i)
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, convMac)
	if err != nil {
		return "", err
	}
	newMac := net.HardwareAddr(buf.Bytes()[2:8])
	return newMac.String(), nil
}

// configureATE configures a single ATE layer 3 interface.
func configureATESubIf(t *testing.T, dut *ondatra.DUTDevice, top gosnappi.Config, atePort *ondatra.Port, localAS uint32,
	tgAttr attrs.Attributes, ateIPs, dutIPs portIpList, connectionType string, advertiseRoute bool) {
	t.Helper()

	localASNum := localAS
	for nhIndex := 0; nhIndex < nextHopCount; nhIndex++ {
		vlanID := uint32(nhIndex)
		if deviations.NoMixOfTaggedAndUntaggedSubinterfaces(dut) {
			vlanID = uint32(nhIndex) + 1
		}

		if connectionType == "EXTERNAL" {
			localASNum = localAS + uint32(nhIndex*100)
		}

		name := fmt.Sprintf(`%s%d`, tgAttr.Name, vlanID)
		mac, _ := incrementMAC(tgAttr.MAC, nhIndex+1)

		ateSubPort := attrs.Attributes{
			Name:    name,
			IPv4:    ateIPs.v4[nhIndex],
			IPv4Len: tgAttr.IPv4Len,
			IPv6:    ateIPs.v6[nhIndex],
			IPv6Len: tgAttr.IPv6Len,
			MAC:     mac,
		}

		dutSubPort := attrs.Attributes{
			IPv4:    dutIPs.v4[nhIndex],
			IPv4Len: tgAttr.IPv4Len,
			IPv6:    dutIPs.v6[nhIndex],
			IPv6Len: tgAttr.IPv6Len,
		}

		configureATE(t, top, atePort, vlanID, localASNum, ateSubPort, dutSubPort, connectionType, advertiseRoute)

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
		t.Logf("Waiting for BGP neighbor to establish...")
		status, ok := gnmi.Watch(t, dut, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[oc.E_Bgp_Neighbor_SessionState]) bool {
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

func applyBgpPolicy(policyName string, dut *ondatra.DUTDevice, isV4 bool) *oc.NetworkInstance_Protocol {
	d := &oc.Root{}
	ni1 := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	niProto := ni1.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	bgp := niProto.GetOrCreateBgp()

	pg := bgp.GetOrCreatePeerGroup("SRC")
	pg.PeerGroupName = ygot.String("SRC")

	if deviations.RoutePolicyUnderAFIUnsupported(dut) {
		//policy under peer group
		pg.GetOrCreateApplyPolicy().ImportPolicy = []string{policyName}
		return niProto
	}

	aftType := oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST
	if isV4 {
		aftType = oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST
	}

	afisafi := pg.GetOrCreateAfiSafi(aftType)
	afisafi.Enabled = ygot.Bool(true)
	rpl := afisafi.GetOrCreateApplyPolicy()
	rpl.SetExportPolicy([]string{policyName})

	return niProto
}

func disableBgpNeighbor(t *testing.T, dut *ondatra.DUTDevice, peerList []string, isV4, enabled bool) {
	t.Helper()

	dutConfPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	d := &oc.Root{}
	ni1 := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	ni_proto := ni1.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	bgp := ni_proto.GetOrCreateBgp()

	for _, peer := range peerList {
		neighbor := bgp.GetOrCreateNeighbor(peer)
		neighbor.Enabled = ygot.Bool(enabled)

		if isV4 {
			afisafi := neighbor.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
			afisafi.Enabled = ygot.Bool(enabled)
			neighbor.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).Enabled = ygot.Bool(enabled)
		} else {
			afisafi6 := neighbor.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
			afisafi6.Enabled = ygot.Bool(enabled)
			neighbor.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Enabled = ygot.Bool(enabled)
		}
	}

	t.Log("Disable BGP neighbors on DUT")
	gnmi.Update(t, dut, dutConfPath.Config(), ni_proto)
}

func disableBGP(nbr string) {
	ceaseAction := gosnappi.NewControlAction().SetChoice(gosnappi.ControlActionChoice.PROTOCOL)
	ceaseAction.Protocol().SetChoice(gosnappi.ActionProtocolChoice.BGP).Bgp().
		SetChoice(gosnappi.ActionProtocolBgpChoice.NOTIFICATION).
		Notification().SetNames([]string{})

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
	fmt.Println(bytes)
	f, err := os.Create(fileName)
	// CreateTemp(".", "pcap")

	if err != nil {
		t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
	}
	if _, err := f.Write(bytes); err != nil {
		t.Fatalf("ERROR: Could not write bytes to pcap file: %v\n", err)
	}
	f.Close()
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

				if openBgpMessage[i] == bgpCapability {
					fmt.Println(openBgpMessage[i+bgpCapabilityOffset])
					capabilitySkipCount := int(openBgpMessage[i+bgpCapabilityOffset])

					fmt.Println(openBgpMessage[i+addPathOffset])
					if openBgpMessage[i+addPathOffset] == bgpAddPathMessage {
						if openBgpMessage[i+v4CapabilityOffset] == addPathCapability && openBgpMessage[i+v6CapabilityOffset] == addPathCapability {
							return true
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
		result = verifyAddPathCapability(t, packet, addPathSendRecv)
		if result {
			t.Log("Add path capability verification successful")
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
		// spew.Dump(bgpPrefixes)
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
		gnmi.OTG().BgpPeer(portName+".BGP4.peer").UnicastIpv6Prefix(bgpAdvPrefix, 32, origin, expectedPathID).State(),
		time.Minute,
		func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv6Prefix]) bool {
			_, present := v.Val()
			return present
		}).Await(t)

	if ok {
		bgpPrefix := gnmi.Get(t, ate.OTG(), gnmi.OTG().BgpPeer(portName+".BGP4.peer").UnicastIpv6Prefix(bgpAdvPrefix, 32, origin, expectedPathID).State())
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
			} else {
				nhAddress = verifyPrefixAddPathV4(t, dut, ate, portName, bgpPrefix, onePathID)
			}
			nhList = append(nhList, nhAddress)
		}
		if reflect.DeepEqual(nhList, expectedNextHops) {
			t.Log("Next hop verification successful")
		} else {
			t.Errorf("Next hop mismatch: got %v, want %v", nhList, expectedNextHops)
		}
	}
	t.Log("Scale verification for prefixes, nh and path ID successful")
}

func verifyPrefixes(t *testing.T, dut *ondatra.DUTDevice, prefix string) {
	// Build the GNMI Get request
	path := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().Ipv4EntryAny().State()
	abc := dut.GNMIOpts().GNMIOpts()
	abc.WithYGNMIOpts()
	// Send the GNMI Get request and wait for the response
	resp := gnmi.GetAll(t, dut, path)

	fmt.Print(resp)
}

func configureMaxPaths(t *testing.T, dut *ondatra.DUTDevice, nbrAddress string, sendMax uint8) {
	t.Helper()

	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()

	configPathNbr4 := bgpPath.Neighbor(nbrAddress).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().SendMax().Config()
	gnmi.Update(t, dut, configPathNbr4, sendMax)

	configPathNbr6 := bgpPath.Neighbor(nbrAddress).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().SendMax().Config()
	gnmi.Update(t, dut, configPathNbr6, sendMax)

	// configPathGlobal4 := bgpPath.Global().AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).AddPaths().SendMax().Config()
	// gnmi.Update(t, dut, configPathGlobal4, sendMax)

	// configPathGlobal6 := bgpPath.Global().AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).AddPaths().SendMax().Config()
	// gnmi.Update(t, dut, configPathGlobal6, sendMax)

}

func GenerateIfaceAddresses() {

	// Increment of 4 for /30 v4 and /126 v6 subnets
	incrFactor := 4

	ifaceCount := 2
	dutEbgp1Ip.v4 = append(dutEbgp1Ip.v4, generateIPv4Addresses(dutEbgp1.IPv4, ifaceCount, incrFactor)...)
	dutEbgp2Ip.v4 = append(dutEbgp2Ip.v4, generateIPv4Addresses(dutEbgp2.IPv4, ifaceCount, incrFactor)...)
	dutEbgp1Ip.v6 = append(dutEbgp1Ip.v6, generateIPv6Addresses(dutEbgp1.IPv6, ifaceCount, incrFactor)...)
	dutEbgp2Ip.v6 = append(dutEbgp2Ip.v6, generateIPv6Addresses(dutEbgp2.IPv6, ifaceCount, incrFactor)...)

	ateEbgp1Ip.v4 = append(ateEbgp1Ip.v4, generateIPv4Addresses(ateEbgp1.IPv4, ifaceCount, incrFactor)...)
	ateEbgp2Ip.v4 = append(ateEbgp2Ip.v4, generateIPv4Addresses(ateEbgp2.IPv4, ifaceCount, incrFactor)...)
	ateEbgp1Ip.v6 = append(ateEbgp1Ip.v6, generateIPv6Addresses(ateEbgp1.IPv6, ifaceCount, incrFactor)...)
	ateEbgp2Ip.v6 = append(ateEbgp2Ip.v6, generateIPv6Addresses(ateEbgp2.IPv6, ifaceCount, incrFactor)...)

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

type testCase struct {
	desc           string
	bgpConfigLevel string
}

func TestAddPathSendRecv(t *testing.T) {
	t.Helper()
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")

	topo := ate.OTG()
	top := topo.NewConfig(t)
	top.Ports().Add().SetName(ate.Port(t, "port1").ID())
	top.Ports().Add().SetName(ate.Port(t, "port2").ID())
	ibgpPort1 := top.Ports().Add().SetName(ate.Port(t, "port3").ID())
	top.Ports().Add().SetName(ate.Port(t, "port4").ID())
	top.Ports().Add().SetName(ate.Port(t, "port5").ID())

	GenerateIfaceAddresses()

	cases := []testCase{{
		desc:           "Verify Test1 and Test2 with bgp configs at global level",
		bgpConfigLevel: "global",
	},
	//  {
	// 	desc:           "Verify Test1 and Test2 with bgp configs at peer level",
	// 	bgpConfigLevel: "peer",
	// }, {
	// 	desc:           "Verify Test1 and Test2 with bgp configs at neighbor level",
	// 	bgpConfigLevel: "neighbor",
	// }
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			// tc.testAddPath(t, dut, ate, ibgpPort1)
			tc.testAddPathScaling(t, dut, ate, ibgpPort1)
		})
	}

}

func (tc *testCase) testAddPath(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, atePort gosnappi.Port) {
	t.Log(tc.desc)

	topo := ate.OTG()
	top := topo.NewConfig(t)
	top.Ports().Add().SetName(ate.Port(t, "port1").ID())
	top.Ports().Add().SetName(ate.Port(t, "port2").ID())
	atePort = top.Ports().Add().SetName(ate.Port(t, "port3").ID())
	top.Ports().Add().SetName(ate.Port(t, "port4").ID())
	top.Ports().Add().SetName(ate.Port(t, "port5").ID())

	ap1 := ate.Port(t, "port1")
	ap2 := ate.Port(t, "port2")
	ap3 := ate.Port(t, "port3")
	ap4 := ate.Port(t, "port4")
	ap5 := ate.Port(t, "port5")

	configureDUT(t, dut)

	routeCountv4 = *ygot.Uint32(1)
	routeCountv6 = *ygot.Uint32(1)
	nextHopCount = 2
	advertiseRoute := true

	configureATE(t, top, ap1, 0, ebgpAteAS1, ateEbgp1, dutEbgp1, "EXTERNAL", advertiseRoute)
	configureATE(t, top, ap2, 0, ebgpAteAS2, ateEbgp2, dutEbgp2, "EXTERNAL", advertiseRoute)
	configureATE(t, top, ap3, 0, globalAS, ateIbgp1, dutIbgp1, "INTERNAL", advertiseRoute)
	configureATE(t, top, ap4, 0, globalAS, ateIbgp2, dutIbgp2, "INTERNAL", advertiseRoute)
	configureATE(t, top, ap5, 0, globalAS, ateIbgp3, dutIbgp3, "INTERNAL", false)

	// Add packet capture config
	top.Captures().Add().SetName("bgpcapture").SetPortNames([]string{atePort.Name()}).SetFormat(gosnappi.CaptureFormat.PCAP)
	t.Log(top.Msg().GetCaptures())
	ate.OTG().PushConfig(t, top)

	startPacketCapture(t, top, ate, atePort)
	ate.OTG().StartProtocols(t)

	bgpNbrs := []string{ateEbgp1.IPv4, ateEbgp2.IPv4, ateIbgp1.IPv4, ateIbgp2.IPv4, ateIbgp3.IPv4}
	verifyBGPSessionState(t, dut, bgpNbrs, oc.Bgp_Neighbor_SessionState_ESTABLISHED)

	//verify that the DUT negotiated addpath cability with Send/Receive field set to "3"
	fileName := savePacketCapture(t, top, ate, atePort)
	verifyPacket(t, fileName, addPathSendRecv)

	// Verify that the DUT is advertising multiple paths to prefix-1 to RRCs ATE3 and ATE4
	// as well as to the RRS ATE5 with different path-ids
	expectedPathID := []uint32{1, 2}
	nextHopsv4 := []string{ateEbgp1.IPv4, ateEbgp2.IPv4}
	verifyPrefixAddPath(t, dut, ate, ateIbgp1.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID)
	verifyPrefixAddPath(t, dut, ate, ateIbgp2.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID)
	verifyPrefixAddPath(t, dut, ate, ateIbgp3.Name, []string{advertisedRoutesv4Ebgp}, nextHopsv4, expectedPathID)

	//Verify that the DUT advertises multiple paths for prefix-2 to ATE5 with different path-ids
	expectedPathID = []uint32{1, 2, 3, 4}
	// verifyPrefixAddPath(t, dut, ate, ateIbgp3.Name, advertisedRoutesv4Ibgp, expectedPathID)

	//Verify that ATE5 receives only 3 different paths (out of 4) w/ unique path-ids from DUT for prefix-2
	maxPaths := uint8(3)
	configureMaxPaths(t, dut, ateIbgp3.IPv4, maxPaths)
	expectedPathID = []uint32{1, 2, 3}
	// verifyPrefixAddPath(t, dut, ate, ateIbgp3.Name, advertisedRoutesv4Ibgp, expectedPathID)

	ate.OTG().StopProtocols(t)
	time.Sleep(20 * time.Second)

}

func (tc *testCase) testAddPathScaling(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, atePort gosnappi.Port) {
	t.Log(tc.desc)

	topo := ate.OTG()
	top := topo.NewConfig(t)
	top.Ports().Add().SetName(ate.Port(t, "port1").ID())
	top.Ports().Add().SetName(ate.Port(t, "port2").ID())
	atePort = top.Ports().Add().SetName(ate.Port(t, "port3").ID())
	top.Ports().Add().SetName(ate.Port(t, "port4").ID())
	top.Ports().Add().SetName(ate.Port(t, "port5").ID())

	ap1 := ate.Port(t, "port1")
	ap2 := ate.Port(t, "port2")
	ap3 := ate.Port(t, "port3")
	ap4 := ate.Port(t, "port4")
	ap5 := ate.Port(t, "port5")

	configureDUT(t, dut)

	advertiseRoute := true
	routeCountv4 = *ygot.Uint32(50000)
	routeCountv6 = *ygot.Uint32(100000)
	// nextHopCount = 2

	// configureATESubIf(t, dut, top, ap1, ebgpAteAS1, ateEbgp1, ateEbgp1Ip, dutEbgp1Ip, "EXTERNAL", false)
	// configureATESubIf(t, dut, top, ap2, ebgpAteAS2, ateEbgp2, ateEbgp2Ip, dutEbgp2Ip, "EXTERNAL", false)

	nextHopCount = 32

	// configureATESubIf(t, dut, top, ap3, globalAS, ateIbgp1, ateIbgp1Ip, dutIbgp1Ip, "INTERNAL", advertiseRoute)
	// configureATESubIf(t, dut, top, ap4, globalAS, ateIbgp2, ateIbgp2Ip, dutIbgp2Ip, "INTERNAL", advertiseRoute)

	configureATE(t, top, ap1, 0, ebgpAteAS1, ateEbgp1, dutEbgp1, "EXTERNAL", false)
	configureATE(t, top, ap2, 0, ebgpAteAS2, ateEbgp2, dutEbgp2, "EXTERNAL", false)
	configureATE(t, top, ap3, 0, globalAS, ateIbgp1, dutIbgp1, "INTERNAL", advertiseRoute)
	configureATE(t, top, ap4, 0, globalAS, ateIbgp2, dutIbgp2, "INTERNAL", advertiseRoute)

	configureATE(t, top, ap5, 0, globalAS, ateIbgp3, dutIbgp3, "INTERNAL", false)

	ate.OTG().PushConfig(t, top)
	ate.OTG().StartProtocols(t)

	bgpNbrs := []string{ateEbgp1.IPv4, ateEbgp2.IPv4, ateIbgp1.IPv4, ateIbgp2.IPv4, ateIbgp3.IPv4}
	verifyBGPSessionState(t, dut, bgpNbrs, oc.Bgp_Neighbor_SessionState_ESTABLISHED)

	//Verify that the DUT advertises multiple paths for prefix-2 to ATE5 with different path-ids
	expectedPathID := []uint32{}

	for pathID := 1; pathID <= 64; pathID++ {
		expectedPathID = append(expectedPathID, uint32(pathID))
	}

	advPrefixScalev4 := generateIPv4Addresses(advertisedRoutesv4Ibgp, int(routeCountv4), 1)
	// advPrefixScalev6 := generateIPv6Addresses(advertisedRoutesv6Ibgp, int(routeCountv6), 1)
	nextHopsv4 := append(ateIbgp1Ip.v4, ateIbgp2Ip.v4...)
	// nextHopsv6 := append(ateIbgp1Ip.v6, ateIbgp2Ip.v6...)

	verifyPrefixAddPath(t, dut, ate, ateIbgp3.Name, advPrefixScalev4[:4], nextHopsv4, expectedPathID)
	// verifyPrefixAddPathScale(t, dut, ate, ateIbgp3.Name, advPrefixScalev6[:500], nextHopsv6, expectedPathID)
	// verifyPrefixes(t, dut, advPrefixScalev4[5])
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
