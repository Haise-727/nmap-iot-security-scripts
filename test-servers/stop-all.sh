#!/bin/sh
cd "$(dirname "$0")"
kill "$(cat .pub.pid)" "$(cat .coap.pid)" 2>/dev/null
pkill -f 'mosquitto -c mosquitto.conf'
rm -f .pub.pid .coap.pid
