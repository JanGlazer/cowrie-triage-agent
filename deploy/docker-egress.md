# Docker egress restriction

The honeypot container may only open outbound TCP connections to ports 80 and 443 (Cowrie needs
them for its own `wget`/`curl` emulation that records download attempts). Everything else from the
container, including SSH (22) and SMTP (25), is dropped. This stops a captured bot from using the
honeypot to scan, brute-force or relay mail.

Rules live in the `DOCKER-USER` chain, which Docker evaluates before its own forwarding rules and
never overwrites. Example (adjust the bridge interface to your Compose network, `docker network ls`):

```bash
BR=br-xxxxxxxxxxxx        # bridge of the Cowrie Compose network
EXT=eth0                  # host's public interface

# replies to inbound connections (attackers talking to the honeypot) stay allowed
sudo iptables -I DOCKER-USER 1 -i "$BR" -o "$EXT" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
sudo iptables -I DOCKER-USER 2 -i "$BR" -o "$EXT" -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j RETURN
sudo iptables -I DOCKER-USER 3 -i "$BR" -o "$EXT" -p udp --dport 53 -j RETURN   # DNS, only if your setup needs it
sudo iptables -I DOCKER-USER 4 -i "$BR" -o "$EXT" -j DROP

sudo apt install iptables-persistent && sudo netfilter-persistent save
```

Verify from inside the container: `curl -sI https://example.com` works, `nc -zv -w3 example.com 25` times out.

Other hardening on the host:
- Real SSH on a non-standard port, key-only, no root login; Cowrie gets port 22 (mapped to 2222 in the container).
- Docker log rotation (`max-size`, `max-file`) so a burst of traffic cannot fill the disk.
- Unattended security upgrades.
- Analysis scripts run as an unprivileged user that can read, but not write, the Cowrie log directory.
