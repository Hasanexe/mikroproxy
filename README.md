# MikroProxy

MikroProxy is a lightweight SOCKS5/HTTP forward proxy written in Go. It aims for minimal overhead, no caching, no traffic modification, no filtering, no authentication.

## Features

- **SOCKS5** or **HTTP** modes (`proxy_mode`).
- IP-based allowlisting via `allowed_ip` (CIDR, IPv4 only).
- Minimal logging – no traffic inspection.

## Installation

Download the latest `.deb` package from [Releases](https://github.com/hasanexe/mikroproxy/releases).

Install using:

```bash
sudo dpkg -i mikroproxy_<version>.deb
```

## Configuration

By default, MikroProxy reads `/etc/mikroproxy.conf`, or you can pass `--config=/path/to/mikroproxy.conf`. Example:

```ini
proxy_mode = http
port = 3128
log_file = /var/log/mikroproxy.log
log_level = debug
allowed_ip = 192.168.1.0/24
allowed_ip = 10.0.0.0/8

idle_timeout = 30s
buffer_size = 65536
log_buffer_size = 1000
```

**Key fields**:

- `proxy_mode`: `http` or `socks`
- `port`: Listening port (default 3128)
- `log_file`: Path for logs
- `log_level`: `debug`, `basic` or `off`
- `allowed_ip`: One per line, CIDR format (IPv4 only)
- `idle_timeout`: Connection idle timeout (e.g., `30s`)
- `buffer_size`: Internal buffer size for copy operations
- `log_buffer_size`: Log channel buffer size (number of queued messages)

## Usage

MikroProxy runs automatically as a systemd service. Manage it with:

```bash
sudo systemctl status mikroproxy
sudo systemctl restart mikroproxy
sudo systemctl stop mikroproxy
```

## Testing

### HTTP Mode

```bash
curl -x http://127.0.0.1:3128 http://example.com
```

### SOCKS5 Mode

```bash
curl --socks5 127.0.0.1:3128 http://example.com
```

Check `/var/log/mikroproxy.log` (or your configured file) for connection logs.

## License

MikroProxy is licensed under the [MIT License](https://opensource.org/licenses/MIT).
