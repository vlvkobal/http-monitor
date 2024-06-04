package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	snapshotLen   int32 = 1024
	promiscuous         = false
	err           error
	timeout       = pcap.BlockForever
	handle        *pcap.Handle
	packetSource  *gopacket.PacketSource
	mu            sync.Mutex
	requests      = make(map[string]int)
	responseTimes = make(map[string][]time.Duration)
)

func main() {
	interfacePtr := flag.String("i", "", "Network interface to capture packets from")
	filePtr := flag.String("f", "", "PCAP file to parse")

	flag.Parse()

	if *interfacePtr == "" && *filePtr == "" {
		log.Fatal("Usage: ./program -i <network interface> or ./program -f <pcap file>")
	}

	packets := make(chan gopacket.Packet)

	// Check if input is a file or interface
	if *interfacePtr != "" {
		// It's a network interface
		handle, err = pcap.OpenLive(*interfacePtr, snapshotLen, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
		go func() {
			for packet := range packetSource.Packets() {
				packets <- packet
			}
		}()
	} else if *filePtr != "" {
		// It's a pcap file
		f, err := os.Open(*filePtr)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		reader, err := pcapgo.NewReader(f)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				data, ci, err := reader.ReadPacketData()
				if err != nil {
					break
				}
				packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
				packet.Metadata().CaptureInfo = ci
				packets <- packet
			}
		}()
	}

	go printMetrics()

	for packet := range packets {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	// Check for HTTP layers
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		if strings.Contains(payload, "HTTP/1.1") {
			// Decode HTTP traffic
			scanner := bufio.NewScanner(strings.NewReader(payload))
			var url, host string
			lines := []string{}

			for scanner.Scan() {
				line := scanner.Text()
				lines = append(lines, line)
				if strings.HasPrefix(line, "Host:") {
					host = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
				}
			}

			timestamp := packet.Metadata().CaptureInfo.Timestamp.Format(time.RFC3339)

			for _, line := range lines {
				if strings.HasPrefix(line, "GET") || strings.HasPrefix(line, "POST") {
					if host == "" {
						fmt.Println("No host header found")
					}
					url = "http://" + host + strings.Fields(line)[1] // Add protocol for clarity
					mu.Lock()
					requests[url]++
					mu.Unlock()
					fmt.Printf("[%s] Request URL: %s\n", timestamp, url)
					fmt.Printf("[%s] %s\n", timestamp, line)
				}
				if strings.HasPrefix(line, "HTTP/1.1") {
					responseTime := time.Now()
					mu.Lock()
					responseTimes[url] = append(responseTimes[url], responseTime.Sub(packet.Metadata().CaptureInfo.Timestamp))
					mu.Unlock()
					fmt.Printf("[%s] %s\n", timestamp, line)
				}
			}
		}
	}
}

func printMetrics() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		mu.Lock()
		if len(requests) == 0 {
			fmt.Printf("[%s] No requests recorded.\n", time.Now().Format(time.RFC3339))
		} else {
			for url, count := range requests {
				if count > 0 {
					avgResponseTime := calculateAverageResponseTime(responseTimes[url])
					fmt.Printf("[%s] URL: %s, Requests: %d, Average Response Time: %v\n", time.Now().Format(time.RFC3339), url, count, avgResponseTime)
				} else {
					fmt.Printf("[%s] URL: %s, Requests: %d, No response times recorded.\n", time.Now().Format(time.RFC3339), url, count)
				}
			}
		}
		requests = make(map[string]int)
		responseTimes = make(map[string][]time.Duration)
		mu.Unlock()
	}
}

func calculateAverageResponseTime(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}
	var total time.Duration
	for _, t := range times {
		total += t
	}
	return total / time.Duration(len(times))
}
