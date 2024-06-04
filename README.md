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

## Running

```sh
sudo ./http-monitor eth0
```

## Test Sites

- [example.com](http://example.com)
- [example.org](http://example.org)
- [httpbin.org](http://httpbin.org)

### Example of Generating a Test Request

```sh
curl --http1.1 httpbin.org/status/204
```

### Example of Recording a Test File

```sh
sudo tcpdump -i eth0 -n host example.com -w test.pcap
```
