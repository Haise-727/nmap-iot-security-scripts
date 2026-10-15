#!/bin/sh
# Publishes fake sensor readings every second so the script has live topics to find.
while true; do
  mosquitto_pub -h 127.0.0.1 -p 1883 -t sensors/temp -m "$((20 + RANDOM % 10))"
  mosquitto_pub -h 127.0.0.1 -p 1883 -t test/topic -m "hello"
  sleep 1
done
