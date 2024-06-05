package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	timestampFormat   = "2006-01-02 15:04:05"
	connectionTimeout = 10 * time.Minute
	cleanupFrequency  = 5 * time.Minute
)

var (
	snapshotLen    int32 = 1024
	err            error
	promiscuous    = false
	timeout        = pcap.BlockForever
	handle         *pcap.Handle
	packetSource   *gopacket.PacketSource
	mu             sync.Mutex
	lastPcapPacket = make(chan gopacket.Packet, 1)
	requests       = make(map[string]int)
	responseTimes  = make(map[string][]time.Duration)
	tcpMap         = make(map[PacketKey]tcpConnection)
	filePtr        *string
	summaryPtr     *bool
	statsMessages  []string
	done           = make(chan bool)
)

type PacketKey struct {
	SrcIP   gopacket.Endpoint
	DstIP   gopacket.Endpoint
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
	Seq     uint32
}

type tcpConnection struct {
	url       string
	timestamp time.Time
}

func main() {
	interfacePtr := flag.String("i", "", "Network interface to capture packets from")
	filePtr = flag.String("f", "", "PCAP file to parse")
	summaryPtr = flag.Bool("s", false, "Print summary at the end")

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
			log.Fatalf("Failed to open interface %s: %v", *interfacePtr, err)
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
			log.Fatalf("Failed to open pcap file %s: %v", *filePtr, err)
		}
		defer f.Close()
		reader, err := pcapgo.NewReader(f)
		if err != nil {
			log.Fatalf("Failed to read pcap file %s: %v", *filePtr, err)
		}
		go func() {
			for {
				data, ci, err := reader.ReadPacketData()
				if err != nil {
					if err == io.EOF {
						close(lastPcapPacket)
						done <- true
						break
					}
					log.Printf("Error reading packet data from %s: %v\n", *filePtr, err)
					continue
				}
				packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
				packet.Metadata().CaptureInfo = ci
				packets <- packet
			}
		}()
	}

	go printMetrics()

	go cleanupStaleConnections()

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

	// Check for TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// Check for IP layer
	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return
	}

	srcIP, dstIP := ipLayer.NetworkFlow().Endpoints()

	// Check for HTTP layers
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		payload := string(applicationLayer.Payload())

		// Skip packets that do not contain "HTTP/1.1"
		if !strings.Contains(payload, "HTTP/1.1") {
			return
		}

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

		timestamp := packet.Metadata().CaptureInfo.Timestamp

		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}

			switch fields[0] {
			case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH":
				// Check if Host header is present
				if host == "" {
					fmt.Println("No host header found")
					return
				}
				// Check if there are at least two fields
				if len(fields) < 2 {
					fmt.Println("Invalid HTTP request line")
					return
				}
				url = "http://" + host + fields[1] // Add protocol for clarity
				key := PacketKey{
					SrcIP:   srcIP,
					DstIP:   dstIP,
					SrcPort: tcp.SrcPort,
					DstPort: tcp.DstPort,
					Seq:     tcp.Seq,
				}
				mu.Lock()
				requests[url]++
				tcpMap[key] = tcpConnection{url, timestamp}
				mu.Unlock()
				fmt.Printf("[%s] Request URL: %s\n", timestamp.Format(timestampFormat), url)
				fmt.Printf("[%s] %s\n", timestamp.Format(timestampFormat), line)
			case "HTTP/1.1":
				// Check if it's a valid HTTP/1.1 response status line
				statusCodeRe := regexp.MustCompile(`^[1-5][0-9]{2}$`)
				if len(fields) < 2 || !statusCodeRe.MatchString(fields[1]) {
					fmt.Println("Invalid HTTP response status line")
					return
				}
				key := PacketKey{
					SrcIP:   dstIP,
					DstIP:   srcIP,
					SrcPort: tcp.DstPort,
					DstPort: tcp.SrcPort,
					Seq:     tcp.Ack - 1,
				}
				mu.Lock()
				if conn, exists := tcpMap[key]; exists {
					responseTimes[conn.url] = append(responseTimes[conn.url], timestamp.Sub(conn.timestamp))
					delete(tcpMap, key)
				}
				mu.Unlock()
				fmt.Printf("[%s] %s\n", timestamp.Format(timestampFormat), line)
			default:
				// Skip any non-HTTP/1.1 lines that are not recognized
				continue
			}
		}
	}
}

func printMetrics() {
	var currentVirtualMinute time.Time

	if *filePtr == "" { // It's a network interface
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt)

		// Print stats on Ctrl+C
		go func() {
			<-sigs
			printStats(time.Now(), *summaryPtr)

			// Print one more set of stats when exiting the loop
			if *summaryPtr {
				fmt.Print("Summary:\n")
				for _, message := range statsMessages {
					fmt.Print(message)
				}
			}

			os.Exit(0)
		}()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		// Print stats every minute
		for t := range ticker.C {
			printStats(t, *summaryPtr)
		}
	} else { // It's a pcap file
		var firstPacket = true
	loop:
		for {
			select {
			case packet, ok := <-lastPcapPacket:
				if !ok {
					// If the channel is closed, exit the loop
					break loop
				}
				virtualMinute := packet.Metadata().CaptureInfo.Timestamp.Truncate(time.Minute)
				if firstPacket {
					currentVirtualMinute = virtualMinute
					firstPacket = false
					continue
				}
				for !currentVirtualMinute.IsZero() && currentVirtualMinute.Before(virtualMinute) {
					// If a minute was skipped, print a message
					currentVirtualMinute = currentVirtualMinute.Add(time.Minute)
					printStats(currentVirtualMinute, *summaryPtr)
				}
				if !virtualMinute.Equal(currentVirtualMinute) {
					currentVirtualMinute = virtualMinute
					printStats(virtualMinute, *summaryPtr)
				}
			case <-done:
				// If the done channel is closed, exit the loop
				break loop
			}
		}

		// Print one more set of stats when exiting the loop
		currentVirtualMinute = currentVirtualMinute.Add(time.Minute)
		printStats(currentVirtualMinute, *summaryPtr)

		// Print one more set of stats when exiting the loop
		if *summaryPtr {
			fmt.Print("Summary:\n")
			for _, message := range statsMessages {
				fmt.Print(message)
			}
		}

		os.Exit(0)
	}
}

func printStats(timestamp time.Time, storeOnly bool) {
	mu.Lock()
	defer mu.Unlock()

	if len(requests) == 0 {
		message := fmt.Sprintf("[%s] No requests recorded.\n", timestamp.Format(timestampFormat))
		if storeOnly {
			statsMessages = append(statsMessages, message)
		} else {
			fmt.Print(message)
		}
	} else {
		// Get the URLs and sort them
		urls := make([]string, 0, len(requests))
		for url := range requests {
			urls = append(urls, url)
		}
		sort.Strings(urls)

		// Print the stats for each URL
		for _, url := range urls {
			count := requests[url]
			if count > 0 {
				avgResponseTime := calculateAverageResponseTime(responseTimes[url])
				message := fmt.Sprintf("[%s] URL: %s, Requests: %d, Average Response Time: %v\n", timestamp.Format(timestampFormat), url, count, avgResponseTime)
				if storeOnly {
					statsMessages = append(statsMessages, message)
				} else {
					fmt.Print(message)
				}
			} else {
				message := fmt.Sprintf("[%s] URL: %s, Requests: %d, No response times recorded.\n", timestamp.Format(timestampFormat), url, count)
				if storeOnly {
					statsMessages = append(statsMessages, message)
				} else {
					fmt.Print(message)
				}
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

func cleanupStaleConnections() {
	ticker := time.NewTicker(cleanupFrequency)
	defer ticker.Stop()

	for range ticker.C {
		mu.Lock()
		defer mu.Unlock()

		for key, conn := range tcpMap {
			if time.Since(conn.timestamp) > connectionTimeout {
				delete(tcpMap, key)
			}
		}
	}
}
