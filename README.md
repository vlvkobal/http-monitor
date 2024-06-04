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
