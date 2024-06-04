package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const timestampFormat = "2006-01-02 15:04:05"

var (
	snapshotLen    int32 = 1024
	promiscuous          = false
	err            error
	timeout        = pcap.BlockForever
	handle         *pcap.Handle
	packetSource   *gopacket.PacketSource
	mu             sync.Mutex
	lastPcapPacket = make(chan gopacket.Packet, 1)
	requests       = make(map[string]int)
	responseTimes  = make(map[string][]time.Duration)
	filePtr        *string
	done           = make(chan bool)
)

func main() {
	interfacePtr := flag.String("i", "", "Network interface to capture packets from")
	filePtr = flag.String("f", "", "PCAP file to parse")

	flag.Parse()

	if (*interfacePtr == "" && *filePtr == "") || (*interfacePtr != "" && *filePtr != "") {
		log.Fatal("Usage: ", os.Args[0], " -i <network interface> or ", os.Args[0], " -f <pcap file>")
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
					done <- true
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
	// Sync stats for file input
	if *filePtr != "" {
		select {
		case <-done:
			// If done is closed, return without sending on lastPcapPacket
			return
		default:
			lastPcapPacket <- packet
		}
	}

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

			timestamp := packet.Metadata().CaptureInfo.Timestamp.Format(timestampFormat)

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
	var currentVirtualMinute time.Time

	if *filePtr == "" { // It's a network interface
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt)

		// Print sats on Ctrl+C
		go func() {
			<-sigs
			printStats(time.Now())
			os.Exit(0)
		}()

		ticker := time.NewTicker(3 * time.Second) // TODO: restore to 1 minute
		defer ticker.Stop()

		// Print stats every minute
		for t := range ticker.C {
			printStats(t)
		}
	} else { // It's a pcap file
	loop:
		for {
			select {
			case packet, ok := <-lastPcapPacket:
				if !ok {
					// If the channel is closed, exit the loop
					break loop
				}
				virtualMinute := packet.Metadata().CaptureInfo.Timestamp.Truncate(time.Minute)
				if !virtualMinute.Equal(currentVirtualMinute) {
					currentVirtualMinute = virtualMinute
					printStats(virtualMinute)
				}
			case <-done:
				// If the done channel is closed, exit the loop
				break loop
			}
		}

		// Print one more set of stats when exiting the loop
		currentVirtualMinute = currentVirtualMinute.Add(time.Minute)
		printStats(currentVirtualMinute)
		os.Exit(0)
	}
}

func printStats(timestamp time.Time) {
	mu.Lock()
	defer mu.Unlock()

	if len(requests) == 0 {
		fmt.Printf("[%s] No requests recorded.\n", timestamp.Format(timestampFormat))
	} else {
		for url, count := range requests {
			if count > 0 {
				avgResponseTime := calculateAverageResponseTime(responseTimes[url])
				fmt.Printf("[%s] URL: %s, Requests: %d, Average Response Time: %v\n", timestamp.Format(timestampFormat), url, count, avgResponseTime)
			} else {
				fmt.Printf("[%s] URL: %s, Requests: %d, No response times recorded.\n", timestamp.Format(timestampFormat), url, count)
			}
		}
	}
	requests = make(map[string]int)
	responseTimes = make(map[string][]time.Duration)
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
