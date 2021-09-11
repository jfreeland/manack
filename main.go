package main

// this is a lazy attempt to send a 3way handshake with a configurable delay
// between receiving the syn/ack and sending an ack, bypassing the kernel's tcp
// stack by arp spoofing.

import (
	"flag"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
)

var (
	snapLen     int32 = 65535
	promiscuous       = false
	handle      *pcap.Handle
)

// get the local ip and port based on our destination ip
// borrowed from https://github.com/kdar/gorawtcpsyn/blob/master/main.go
func localIPPort(dstip net.IP) (net.IP, int) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}

	// we don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port
		}
	}
	log.Fatal("could not get local ip: " + err.Error())
	return nil, -1
}

func main() {
	var (
		device, host string
		dport        int
	)
	flag.StringVar(&device, "i", "", "interface to use")
	flag.StringVar(&host, "h", "", "ip address or host to target")
	flag.IntVar(&dport, "p", 0, "tcp port to target")
	flag.Parse()

	if device == "" || host == "" || dport == 0 {
		log.Fatal("must provide device, host, port")
	}

	// some basic setup
	iface, err := net.InterfaceByName(device)
	if err != nil {
		log.Fatal(err)
	}
	dstaddrs, err := net.LookupIP(host)
	if err != nil {
		log.Fatal(err)
	}
	dstip := dstaddrs[0].To4()
	dstport := layers.TCPPort(dport)
	ourMAC := iface.HardwareAddr
	gatewayip, err := gateway.DiscoverGateway()
	if err != nil {
		log.Fatal(err)
	}

	// pick a random port to send packets from and get our actual ip
	// should probably get the ip from
	realip, sport := localIPPort(dstip)
	ipParts := strings.Split(realip.To4().String(), ".")
	lastOctetInt, err := strconv.Atoi(ipParts[3])
	if err != nil {
		log.Fatal(err)
	}
	// probably need to do something like `fping -g` and find an open host on the network
	// i'm going to be lazy for now.
	// 13 seems unlucky enough to work here
	newLastOctetString := strconv.Itoa(lastOctetInt + 13)
	ipParts[3] = newLastOctetString
	srcip := strings.Join(ipParts, ".")
	log.Printf("using srcip: %v\n", srcip)
	srcport := layers.TCPPort(sport)

	// assemble our arp poisoning packet so we can bypass kernel tcp stack
	// send out a gARP and tell people to send to us for some host that's not on the network
	gratiutiousArpMAC, err := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if err != nil {
		log.Fatal(err)
	}
	// TODO: should be grabbing this dynamically 😐 laziness
	gatewayMAC, err := net.ParseMAC("cc:f4:11:37:4a:a4")
	if err != nil {
		log.Fatal(err)
	}
	ethLayer := &layers.Ethernet{
		SrcMAC:       ourMAC,
		DstMAC:       gratiutiousArpMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   ourMAC,
		SourceProtAddress: net.ParseIP(srcip).To4(),
		DstHwAddress:      gratiutiousArpMAC,
		DstProtAddress:    gatewayip.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err = gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer); err != nil {
		log.Fatal(err)
	}

	handle, err = pcap.OpenLive(device, snapLen, promiscuous, pcap.BlockForever)
	defer handle.Close()
	if err != nil {
		log.Fatal(err)
	}

	if err = handle.WritePacketData(buf.Bytes()); err != nil {
		log.Fatal(err)
	} else {
		log.Println("arp sent")
	}

	ethLayer = &layers.Ethernet{
		SrcMAC:       ourMAC,
		DstMAC:       gatewayMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(srcip),
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     rand.Uint32(),
		SYN:     true,
		Window:  65535,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer); err != nil {
		log.Fatal(err)
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Fatal(err)
	} else {
		log.Println("sent syn")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if arp != nil {
				//if arp.Operation == layers.ARPRequest && string(arp.DstHwAddress) == ourMAC.String() && string(arp.DstProtAddress) == srcip {
				dstArpIP := string(arp.DstProtAddress)
				// TODO: this doesn't actually work but i'm done fiddling with this for now.
				if arp.Operation == layers.ARPRequest {
					log.Println("received an arp request")
					// log.Printf("%v ~? %v\n", arp.DstHwAddress, ourMAC.String())
					log.Printf("%v ~? %v\n", dstArpIP, srcip)
				}
			}
		} else {
			//log.Println("received non-arp packet")
		}
	}
	// for {
	// 	data, _, err := handle.ReadPacketData()
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	ipPacket := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	// 	if ipPacket.NetworkLayer().NetworkFlow().Dst().String() == srcip {
	// 		tcpPacket := gopacket.NewPacket(data, layers.LayerTypeTCP, gopacket.Default)
	// 		log.Println(ipPacket.String())
	// 		log.Println(tcpPacket.String())
	// 		if tcpLayer := tcpPacket.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	// 			tcp, _ := tcpLayer.(*layers.TCP)
	// 			if tcp.DstPort == srcport {
	// 				log.Printf("Port %d is OPEN\n", dstport)
	// 			} else {
	// 				log.Printf("Port %d is CLOSED\n", dstport)
	// 			}
	// 		}
	// 	}
	// }
}
