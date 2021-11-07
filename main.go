package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

func main() {
	//Find all devices
	// devices, err := pcap.FindAllDevs()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// // Print device information
	// fmt.Println(devices)
	// fmt.Println("Devices found:")
	// for _, device := range devices {
	// 	fmt.Println("\nName: ", device.Name)
	// 	fmt.Println("Description: ", device.Description)
	// 	for _, address := range device.Addresses {
	// 		fmt.Println("- IP address: ", address.IP)
	// 	}
	// }

	handle, err := pcap.OpenLive("\\Device\\NPF_Loopback", defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// if err := handle.SetBPFFilter("arp net 128.3"); err != nil {
	// 	panic(err)
	// }

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()

	for packet := range packets {
		// ipLayer := packet.Layer(layers.LayerTypeIPv4)
		// if ipLayer != nil {
		// 	fmt.Println("IPv4 layer detected.")
		// 	ip, _ := ipLayer.(*layers.IPv4)

		// 	// IP layer variables:
		// 	// Version (Either 4 or 6)
		// 	// IHL (IP Header Length in 32-bit words)
		// 	// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// 	// Checksum, SrcIP, DstIP
		// 	fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		// 	fmt.Println("Protocol: ", ip.Protocol)
		// 	fmt.Println()
		// }

		// arplayer := packet.Layer(layers.ARPRequest)
		// if arplayer != nil {
		// 	fmt.Println(string(arplayer.LayerPayload()))
		// }

		arpReply := packet.Layer(layers.ARPReply)
		if arpReply != nil {
			arp, success := arpReply.(*layers.ARP)
			if success {
				fmt.Println(string(arp.Protocol))
			}
		}

		// applicationLayer := packet.ApplicationLayer()
		// if applicationLayer != nil {
		// 	fmt.Println("Application layer/Payload found.")
		// 	fmt.Printf("%s\n", applicationLayer.Payload())

		// 	// Search for a string inside the payload
		// 	if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
		// 		fmt.Println("HTTP found!")
		// 	}
		// }

	}
}
