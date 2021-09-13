package main

// this is a lazy attempt to send a 3way handshake with a configurable delay
// between receiving the syn/ack and sending an ack, bypassing the kernel's tcp
// stack by arp spoofing.

// there's a whole lot of room for improvement here.  maybe there's something
// that does this already, but i couldn't find it.

import (
	"flag"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/j-keck/arping"
	"github.com/jackpal/gateway"
)

var (
	snapLen     int32 = 65535
	promiscuous       = false
	handle      *pcap.Handle
	err         error
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

// getARPRequestIP is gross because the byte slice the DstProtAddress comes back
// as is actually ints?  do we actually need to respond to multiple arp requests
// in the future?  it might (?) help if we want to upgrade to TLS
// in the future and continue spoofing.
func getARPRequestIP(ipBytes []byte) net.IP {
	ipOctetStrings := make([]string, 4)
	for i, octet := range ipBytes {
		octetString := strconv.Itoa(int(octet))
		ipOctetStrings[i] = octetString
	}
	ipString := strings.Join(ipOctetStrings, ".")
	ip := net.ParseIP(ipString)
	return ip
}

// sendARP sends an arp response
// initially we send a gratuitous arp response to spoof an open host so we can
// avoid using our host tcp stack
func sendARP(handle *pcap.Handle, config Config, gARP bool) error {
	var dstHWAddress net.HardwareAddr
	if gARP {
		dstHWAddress = config.gARPMAC
	} else {
		dstHWAddress = config.dstMAC
	}
	ethLayer := &layers.Ethernet{
		SrcMAC:       config.srcMAC,
		DstMAC:       config.dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   config.srcMAC,
		SourceProtAddress: config.srcIP.To4(),
		DstHwAddress:      dstHWAddress,
		DstProtAddress:    config.dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err = gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer); err != nil {
		return err
	}
	if err = handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	log.Println("arp sent")
	return nil
}

// sendTCPPacket sends a TCP packet with relevant ethernet and IP headers
// this should be way cleaner.  should probably assemble packet in a separate
// function from sending it.
func sendTCPPacket(handle *pcap.Handle, config Config, seqNum, ackNum uint32, syn, ack bool, payload []byte) error {
	ethLayer := &layers.Ethernet{
		SrcMAC:       config.srcMAC,
		DstMAC:       config.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    config.srcIP,
		DstIP:    config.dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: config.srcPort,
		DstPort: config.dstPort,
		Seq:     seqNum,
		SYN:     syn,
		Ack:     ackNum,
		ACK:     ack,
		Window:  65535,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		log.Fatal(err)
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Fatal(err)
	} else {
		log.Println("packet sent")
	}
	return nil
}

// Config stores values we need across multiple packets
type Config struct {
	srcMAC, dstMAC, gARPMAC net.HardwareAddr
	srcIP, dstIP, gatewayIP net.IP
	srcPort, dstPort        layers.TCPPort
}

// config is a mess.
func config(device, host string, dport int) Config {
	// this is a mess and needs major cleanup.
	iface, err := net.InterfaceByName(device)
	if err != nil {
		log.Fatal(err)
	}
	dstaddrs, err := net.LookupIP(host)
	if err != nil {
		log.Fatal(err)
	}
	dstIP := dstaddrs[0].To4()
	dstPort := layers.TCPPort(dport)
	srcMAC := iface.HardwareAddr
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		log.Fatal(err)
	}
	dstMAC, _, err := arping.PingOverIface(gatewayIP, *iface)
	if err != nil {
		log.Fatal(err)
	}

	// pick a random port to send packets from and get our actual ip
	// should probably get the ip from
	realIP, sPort := localIPPort(dstIP)
	ipParts := strings.Split(realIP.To4().String(), ".")
	lastOctetInt, err := strconv.Atoi(ipParts[3])
	if err != nil {
		log.Fatal(err)
	}
	// probably need to do something like `fping -g` and find an open host on the network
	// i'm going to be lazy for now.
	// 13 seems unlucky enough to work here
	newLastOctetString := strconv.Itoa(lastOctetInt + 13)
	ipParts[3] = newLastOctetString
	srcIPString := strings.Join(ipParts, ".")
	log.Printf("using srcip: %v\n", srcIPString)
	srcIP := net.ParseIP(srcIPString)
	srcPort := layers.TCPPort(sPort)

	gratiutiousARPMAC, err := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if err != nil {
		log.Fatal(err)
	}
	// TODO: should be grabbing this dynamically 😐 laziness.  will only work on
	// my personal laptop at the moment.
	// should be listening for arp requests for my actual ip and determine
	// gateway mac from there, or look at network config and send out arp
	// request for gateway ip
	//dstMAC, err := net.ParseMAC("cc:f4:11:37:4a:a4")
	if err != nil {
		log.Fatal(err)
	}
	return Config{
		srcMAC:    srcMAC,
		dstMAC:    dstMAC,
		gARPMAC:   gratiutiousARPMAC,
		srcIP:     srcIP,
		dstIP:     dstIP,
		gatewayIP: gatewayIP,
		srcPort:   srcPort,
		dstPort:   dstPort,
	}
}

func main() {
	var (
		device, host string
		dport, delay int
	)
	flag.StringVar(&device, "i", "", "interface to use")
	flag.StringVar(&host, "h", "", "ip address or host to target")
	flag.IntVar(&dport, "p", 0, "tcp port to target")
	flag.IntVar(&delay, "d", 0, "delay before sending ACK")
	flag.Parse()

	if device == "" || host == "" || dport == 0 {
		log.Fatal("must provide device, host, port")
	}

	config := config(device, host, dport)

	handle, err = pcap.OpenLive(device, snapLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err = sendARP(handle, config, true); err != nil {
		log.Fatalf("error sending gARP: %v\n", err)
	}

	seqNum := rand.Uint32()

	if err = sendTCPPacket(handle, config, seqNum, 0, true, false, nil); err != nil {
		log.Fatalf("error sending SYN: %v\n", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if arp != nil {
				if arp.Operation == layers.ARPRequest {
					var arpRequestIP net.IP
					if len(arp.DstProtAddress) == 4 {
						arpRequestIP = getARPRequestIP(arp.DstProtAddress)
					} else {
						continue
					}
					arpRequestString := arpRequestIP.String()
					srcIPString := config.srcIP.String()
					if arpRequestString == srcIPString {
						sendARP(handle, config, false)
					}
				}
			}
		} else {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if ipLayer != nil && tcpLayer != nil {
				ip := ipLayer.(*layers.IPv4)
				tcp := tcpLayer.(*layers.TCP)
				// TODO: should probably look at received packet's tcp ACK num
				// to make sure it's seqNum + 1
				// should probably also check syn and ack flags
				if ip != nil && tcp != nil {
					dstIPString := ip.DstIP.String()
					srcIPString := config.srcIP.String()
					if dstIPString == srcIPString && tcp.DstPort == config.srcPort {
						if delay != 0 {
							log.Printf("sleeping %v seconds before sending ACK", delay)
							time.Sleep(time.Duration(delay) * time.Second)
						}
						ackNum := tcp.Seq + 1
						// TODO: send an HTTP request as our payload.  long
						// term, upgrade to TLS if we ask for it, try to issue
						// HTTPS request?
						if err := sendTCPPacket(handle, config, seqNum, ackNum, false, true, nil); err != nil {
							log.Fatal(err)
						}
						break
					}
				}
			}
		}
	}
}
