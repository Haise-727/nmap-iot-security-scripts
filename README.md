# Nmap IoT Security Scripts

Two small Nmap (NSE) scripts that check Internet of Things services for risky settings.
Each one extends a script that ships with Nmap, and adds the part the original leaves out: a clear verdict.

| Script | Protocol | Question it answers |
|--------|----------|---------------------|
| [`mqtt-auth-check.nse`](scripts/mqtt-auth-check.nse) | MQTT (TCP 1883) | Does this broker let someone in with no username or password? |
| [`coap-security-check.nse`](scripts/coap-security-check.nse) | CoAP (UDP 5683) | Does this device talk in plain text, and does it show admin looking pages? |

Both scripts only read. They never publish messages, never guess passwords and never change anything on the target, so they sit in Nmap's `safe` category.

## What each script adds to the original

| Original (in [`reference/`](reference)) | What it does | What my version adds |
|---|---|---|
| `mqtt-subscribe.nse` | Lists the topics on a broker | Connects with no credentials on purpose and says `ANON ALLOWED` or `AUTH REQUIRED` before listing topics |
| `coap-resources.nse` | Lists the resources of a CoAP device | Warns that port 5683 is unencrypted, and marks resources like `/admin/config` as `RISK` |

The files in `reference/` are the unchanged Nmap scripts, written by Mak Kolybabi, kept here so you can compare them with mine.

## Example output

An MQTT broker that allows anyone in:

```
1883/tcp open  mqtt
| mqtt-auth-check:
|   Anonymous connect: [ANON ALLOWED] Broker accepted a CONNECT with no credentials
|_  Topics observed: sensors/temp, test/topic
```

The same broker after it was set to require a password:

```
1883/tcp open  mqtt
| mqtt-auth-check:
|_  Anonymous connect: [AUTH REQUIRED] Broker rejected anonymous CONNECT: Not Authorized
```

A CoAP device:

```
5683/udp open  coap
| coap-security-check:
|   Transport: [RISK] Plaintext CoAP on port 5683 -- no DTLS encryption. Secure CoAPs normally runs on UDP/5684.
|   Discovered resources:
|     /sensors/temp: [READABLE]
|_    /admin/config: [RISK] sensitive-looking path, no authentication required
```

All saved scan results, including the plain `nmap` scan from before and the results of the original scripts, are in [`outputs/`](outputs).

## Try it yourself

Everything runs on your own machine (127.0.0.1). Do not point these scripts at hosts you do not own or have permission to test.

You need: Nmap, Mosquitto (the MQTT broker), and Python 3.

```sh
# 1. one time: set up the CoAP test device
python -m venv test-servers/venv
test-servers/venv/bin/pip install -r test-servers/requirements.txt

# 2. start the test servers (an open MQTT broker and a CoAP device)
test-servers/run-all.sh

# 3. run the scripts straight from this folder
nmap -p 1883 --script ./scripts/mqtt-auth-check.nse 127.0.0.1
sudo nmap -sU -p 5683 --script ./scripts/coap-security-check.nse 127.0.0.1

# 4. stop the servers
test-servers/stop-all.sh
```

The CoAP scan needs `sudo` because Nmap uses raw sockets for UDP scans.

To see the `AUTH REQUIRED` result, start the stricter broker instead of the open one:

```sh
cd test-servers
mosquitto_passwd -c -b passwd demo demo123
mosquitto -c mosquitto-secure.conf
```

To install the scripts for every scan, copy them into Nmap's script folder and rebuild its index:

```sh
sudo cp scripts/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

Then you can use `--script mqtt-auth-check` without the path.

## Script options

`mqtt-auth-check.listen-time` sets how many seconds the script listens for messages after it gets in. The default is 3.

```sh
nmap -p 1883 --script mqtt-auth-check --script-args mqtt-auth-check.listen-time=10 127.0.0.1
```

`coap-security-check.uri` sets which path to ask the device for. The default is `/.well-known/core`.

## Repository layout

```
scripts/        my two scripts
reference/      the original Nmap scripts they build on
test-servers/   the local MQTT broker and CoAP device used for testing
outputs/        saved scan results (text and XML)
```

## Limits

* The `RISK` marking in the CoAP script is a simple word match (admin, config, password, cred, secret, key). It is a hint, not proof of a problem.
* The scripts were tested against the local test servers in this repository and Nmap 7.991.

## About

Written by Harsha Vardan M Sakamuri for the Cyber Security course at VIT Chennai.
The scripts use the same license as Nmap, see <https://nmap.org/book/man-legal.html>.
