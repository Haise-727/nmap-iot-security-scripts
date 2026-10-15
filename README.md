# Nmap IoT security scripts

Two custom Nmap NSE scripts that check IoT protocols for risky defaults, plus the local test servers used to demo them.
Everything runs against 127.0.0.1 only.

| Script | Extends | Checks |
|--------|---------|--------|
| `scripts/mqtt-auth-check.nse` | `reference/mqtt-subscribe.nse` | Whether an MQTT broker accepts a connection with no credentials, and which topics it then leaks |
| `scripts/coap-security-check.nse` | `reference/coap-resources.nse` | Whether a CoAP device runs in plaintext (no DTLS) and exposes admin looking resources |

The two files in `reference/` are the stock Nmap scripts (author Mak Kolybabi), included unchanged for comparison.

## Run the demo

```sh
# one time: python venv for the CoAP test server
python -m venv test-servers/venv && test-servers/venv/bin/pip install aiocoap

test-servers/run-all.sh                      # insecure MQTT broker + CoAP device
sudo cp scripts/*.nse /usr/share/nmap/scripts/ && sudo nmap --script-updatedb

nmap -p 1883 --script mqtt-auth-check 127.0.0.1
sudo nmap -sU -p 5683 --script coap-security-check 127.0.0.1

test-servers/stop-all.sh
```

`outputs/` holds the saved results, including the before scan (plain `nmap`), the stock script results, and the result against a broker that requires a password (`mqtt-auth-check-secured.txt`).

Author: Harsha Vardan M Sakamuri
