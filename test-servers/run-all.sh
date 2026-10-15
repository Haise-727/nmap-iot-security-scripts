#!/bin/sh
# Starts both demo servers in the background. Stop them with ./stop-all.sh
cd "$(dirname "$0")"
mosquitto -c mosquitto.conf -d
./mqtt_publisher.sh >/dev/null 2>&1 &
echo $! > .pub.pid
venv/bin/python coap_server.py >/dev/null 2>&1 &
echo $! > .coap.pid
sleep 2
echo "MQTT on 127.0.0.1:1883, CoAP on udp 127.0.0.1:5683"
