# MikroProxy

MikroProxy is a lightweight SOCKS5/HTTP forward proxy written in Go. It aims for minimal overhead, no caching or traffic modification, no filtering, and no authentication.

## Features

- **SOCKS5** or **HTTP** modes, selected via `proxy_mode`
- Simple IP-based allowlisting via `allowed_ip` (CIDR)
- Optional TCP keepalive via `tcpkeepalive`
- Minimal logging – no advanced traffic inspection

## Installation

You can **download** a prebuilt binary or `.deb` package from the [Releases page](https://github.com/yourusername/mikroproxy/releases).

- **Prebuilt Binary**: Place it anywhere (e.g. `/usr/local/bin`) and run it.
- **.deb Package**: Installs the binary, creates a `mikroproxy` user/service, and places default config/log in standard locations. Once installed, start or enable via `systemctl`.

## Configuration

By default, MikroProxy looks for `/etc/mikroproxy.conf`. You can override this by passing `--config=/path/to/config.conf`.

A typical `/etc/mikroproxy.conf` might contain:

```ini
# proxy_mode can be "socks" or "http"
proxy_mode=socks

# Listening port (default 3128)
port=3128

# Path to log file
log_file=/var/log/mikroproxy.log

# IP allowlist in CIDR notation (repeat as needed)
allowed_ip=10.14.0.0/16
allowed_ip=172.18.0.0/16

# (Optional) Enable TCP keepalive by setting "on" or "1"
tcpkeepalive=on
```

### Key Fields

- **`proxy_mode`**: `"socks"` or `"http"`.
- **`port`**: The listening port (e.g. `3128`).
- **`log_file`**: Where logs should be written.
- **`allowed_ip`**: Repeated lines for each CIDR block allowed.
- **`tcpkeepalive`**: If set to `"on"` or `"1"`, keepalive is enabled; otherwise disabled.

## Usage

If you place a config at `/etc/mikroproxy.conf`, just run:

```bash
sudo ./mikroproxy
```

Or specify a custom config path:

```bash
sudo ./mikroproxy --config=/path/to/config.conf
```

## Testing

1. **HTTP Mode**  
   ```bash
   curl -x http://127.0.0.1:3128 http://example.com -v
   ```  
   Expects to see the request forwarded to `example.com`.

2. **SOCKS5 Mode**  
   ```bash
   curl --socks5 127.0.0.1:3128 http://example.com -v
   ```  
   Uses a SOCKS tunnel to request `example.com`.

Check logs at the path configured in `log_file` (defaults to `/var/log/mikroproxy.log`) for connection info.

## License

MikroProxy is released under the [MIT License](https://opensource.org/licenses/MIT). See [LICENSE](LICENSE) for details.
