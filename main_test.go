package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"testing"
)

func TestPCAPFiles(t *testing.T) {
	tests := []struct {
		name         string
		pcapFile     string
		summary      bool
		expectedFile string
	}{
		{
			name:         "Test Diverse",
			pcapFile:     "testdata/test-diverse.pcap",
			summary:      false,
			expectedFile: "testdata/test-diverse-expected.txt",
		},
		{
			name:         "Test Diverse Summary",
			pcapFile:     "testdata/test-diverse.pcap",
			summary:      true,
			expectedFile: "testdata/test-diverse-summary-expected.txt",
		},
		{
			name:         "Test Gaps",
			pcapFile:     "testdata/test-gaps.pcap",
			summary:      false,
			expectedFile: "testdata/test-gaps-expected.txt",
		},
		{
			name:         "Test Gaps Summary",
			pcapFile:     "testdata/test-gaps.pcap",
			summary:      true,
			expectedFile: "testdata/test-gaps-summary-expected.txt",
		},
	}

	// Compile the program
	exePath := "./http-monitor"
	cmd := exec.Command("go", "build", "-o", exePath)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile program: %s", err)
	}
	defer os.Remove(exePath) // Clean up the executable after tests

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture stdout
			tmpFile, err := os.CreateTemp("", "stdout")
			if err != nil {
				t.Fatalf("failed to create temporary file: %s", err)
			}
			defer os.Remove(tmpFile.Name())

			// Run the command
			cmd := exec.Command(exePath, "-f", tt.pcapFile)
			if tt.summary {
				cmd.Args = append(cmd.Args, "-s")
			}
			cmd.Stdout = tmpFile
			cmd.Stderr = &bytes.Buffer{}

			err = cmd.Run()
			if err != nil {
				t.Fatalf("cmd.Run() failed with %s\nStderr: %s", err, cmd.Stderr.(*bytes.Buffer).String())
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

			// Compare outputs
			if string(capturedOutput) != string(expectedOutput) {
				t.Errorf("output does not match expected\nExpected:\n%s\nGot:\n%s", string(expectedOutput), string(capturedOutput))
			}
		})
	}
}
