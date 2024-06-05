# HTTP traffic monitoring

## Prerequisites

### General Requirements

Go, GCC, Git, libpcap should be installed.

### Arch Linux

For Arch Linux users, ensure that `CGO_ENABLED` is set to `1` to enable CGO support. This is necessary for proper compilation of `gopacket`.

```sh
export CGO_ENABLED=1
```

## Installation

```sh
git clone https://github.com/vlvkobal/http-monitoring.git
cd http-monitoring
go mod tidy
go build
```

## Usage

The `http-monitor` tool can be used with the following command-line options:

```sh
Usage of ./http-monitor:
  -f string
        PCAP file to parse
  -i string
        Network interface to capture packets from
  -s    
        Print summary at the end
```

## Test

### Running End to End Tests for Pcap Files

```sh
go test -v
```

### Running End to End Tests for Interfaces

The end-to-end tests for interfaces use virtual network interfaces and `tcpreplay` to replay pcap files. These tests are optional and require `tcpreplay` to be installed and the ability to run `sudo` commands.

To run these tests:
1. Ensure `tcpreplay` is installed.
2. Ensure you can run `sudo` commands.
3. ⚠️ **Warning**: The tests will automatically create and then destroy the virtual interfaces `veth0` and `veth1`. If anything goes wrong you can tear interfaces down using `sudo scripts/teardown_interfaces.sh`.
4. Use the following command to run the tests with the `interfaces` build tag:

```sh
go test -v -tags=interfaces
```

### Sites

- [example.com](http://example.com)
- [example.org](http://example.org)
- [httpbin.org](http://httpbin.org)

### Example of Generating a Test Request

```sh
curl --http1.1 httpbin.org/status/204
```

### Example of Recording a Test File

```sh
sudo tcpdump port 80 -n -i eth0 -w test.pcap
```
