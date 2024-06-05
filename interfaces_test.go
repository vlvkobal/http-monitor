//go:build interfaces

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"testing"
	"time"
)

func runScript(script string) error {
	cmd := exec.Command("sudo", "scripts/"+script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %s", err, stderr.String())
	}
	return nil
}

func removeTimestamps(input string) string {
	// Define a regular expression to match timestamps in the format [YYYY-MM-DD HH:MM:SS]
	re := regexp.MustCompile(`\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]`)
	return re.ReplaceAllString(input, "")
}

func TestInterfaces(t *testing.T) {
	tests := []struct {
		name         string
		pcapFile     string
		summary      bool
		expectedFile string
	}{
		{
			name:         "Test Interface",
			pcapFile:     "testdata/test-interface.pcap",
			summary:      false,
			expectedFile: "testdata/test-interface-expected.txt",
		},
		{
			name:         "Test Interface Summary",
			pcapFile:     "testdata/test-interface.pcap",
			summary:      true,
			expectedFile: "testdata/test-interface-summary-expected.txt",
		},
	}

	// Compile the program
	exePath := "./http-monitor"
	cmd := exec.Command("go", "build", "-o", exePath)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile program: %s", err)
	}
	defer os.Remove(exePath) // Clean up the executable after tests

	// Setup virtual interfaces
	if err := runScript("setup_interfaces.sh"); err != nil {
		t.Fatalf("failed to set up virtual interfaces: %v", err)
	}
	defer func() {
		if err := runScript("teardown_interfaces.sh"); err != nil {
			t.Fatalf("failed to tear down virtual interfaces: %v", err)
		}
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture stdout
			tmpFile, err := os.CreateTemp("", "stdout")
			if err != nil {
				t.Fatalf("failed to create temporary file: %s", err)
			}
			defer os.Remove(tmpFile.Name())

			// Run the program and capture the output
			cmd := exec.Command("sudo", exePath, "-i", "veth1")
			if tt.summary {
				cmd.Args = append(cmd.Args, "-s")
			}
			cmd.Stdout = tmpFile
			cmd.Stderr = &bytes.Buffer{}

			// Start the program in a non-blocking manner
			if err := cmd.Start(); err != nil {
				t.Fatalf("cmd.Start() failed with %s\nStderr: %s", err, cmd.Stderr.(*bytes.Buffer).String())
			}

			// Give the program some time to initialize
			time.Sleep(1 * time.Second)

			// Run tcpreplay to replay the pcap file
			tcpreplayCmd := exec.Command("sudo", "tcpreplay", "--intf1=veth0", tt.pcapFile)
			if err := tcpreplayCmd.Start(); err != nil {
				t.Fatalf("failed to start tcpreplay: %v", err)
			}

			// Give tcpreplay some time to send packets
			time.Sleep(5 * time.Second)

			// Stop the program
			if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
				t.Fatalf("Failed to send SIGINT: %s", err)
			}

			// Wait for the program to exit
			if err := cmd.Wait(); err != nil {
				t.Fatalf("cmd.Wait() failed with %s", err)
			}

			// Read captured output
			tmpFile.Seek(0, 0) // Rewind to the beginning of the file
			capturedOutput, err := io.ReadAll(tmpFile)
			if err != nil {
				t.Fatalf("failed to read captured output: %s", err)
			}

			t.Logf("Captured Output:\n%s", capturedOutput)

			// Read expected output
			expectedOutput, err := os.ReadFile(tt.expectedFile)
			if err != nil {
				t.Fatalf("failed to read expected output file: %s", err)
			}

			// Remove timestamps from both outputs
			capturedOutputWithoutTimestamps := removeTimestamps(string(capturedOutput))
			expectedOutputWithoutTimestamps := removeTimestamps(string(expectedOutput))

			// Compare outputs
			if capturedOutputWithoutTimestamps != expectedOutputWithoutTimestamps {
				t.Errorf("output does not match expected\nExpected:\n%s\nGot:\n%s", expectedOutputWithoutTimestamps, capturedOutputWithoutTimestamps)
			}
		})
	}
}
