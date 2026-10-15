-- mqtt-auth-check.nse
--
-- We "require" (import) Nmap's own mqtt.lua library instead of hand-rolling
-- MQTT's binary CONNECT/SUBSCRIBE packet format (fixed header, variable
-- remaining-length encoding, etc). Every built-in NSE script does the same
-- for its protocol (e.g. ftp-anon.nse requires "ftp"). The original part of
-- THIS script is the security logic below: connecting with NO credentials
-- on purpose and explicitly labelling whether that succeeded, which the
-- built-in mqtt-subscribe.nse does not do.
local mqtt = require "mqtt"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts an MQTT CONNECT handshake with no username/password. If the
broker accepts the anonymous connection, the script briefly subscribes
to the wildcard topic "#" to see whether any live traffic is exposed,
then disconnects. Brokers that accept unauthenticated clients are
flagged as a misconfiguration.

This is a single connect + short subscribe + disconnect: no brute
forcing, no publishing, no persistent connection.
]]

---
-- @usage nmap -p 1883 --script mqtt-auth-check <target>
-- @args mqtt-auth-check.listen-time Seconds to listen for PUBLISH
--       messages after a successful anonymous subscribe, default 3.
-- @output
-- PORT     STATE SERVICE
-- 1883/tcp open  mqtt
-- | mqtt-auth-check:
-- |   Anonymous connect: [ANON ALLOWED] Broker accepted a CONNECT with no credentials
-- |_  Topics observed: test/topic, sensors/temp

author = "Harsha Vardan M Sakamuri"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "auth", "safe"}

-- Only run against hosts/ports that look like an MQTT broker, over TCP.
portrule = shortport.port_or_service({1883, 8883}, {"mqtt", "secure-mqtt"}, "tcp")

action = function(host, port)
  local output = stdnse.output_table()

  -- 1) Try to CONNECT with no username/password fields at all. A
  -- correctly-secured broker should reject this with "Not Authorized"
  -- or similar; a misconfigured one will send back an accepted CONNACK.
  local helper = mqtt.Helper:new(host, port)
  local status, response = helper:connect({})
  if not status then
    -- Couldn't even complete a CONNECT/CONNACK round trip, so this is
    -- probably not an MQTT service at all. Stay silent like other
    -- probe-based discovery scripts do.
    return nil
  end

  if not response.accepted then
    output["Anonymous connect"] = ("[AUTH REQUIRED] Broker rejected anonymous CONNECT: %s"):format(response.reason)
    return output, stdnse.format_output(true, output)
  end

  output["Anonymous connect"] = "[ANON ALLOWED] Broker accepted a CONNECT with no credentials"

  -- 2) Since we got in, subscribe to the wildcard topic "#" (matches
  -- every topic) to see if the broker is also leaking live messages to
  -- anyone who connects.
  local status, sub_response = helper:request("SUBSCRIBE", {["filters"] = {{["filter"] = "#"}}}, "SUBACK")
  if not status then
    output["Topics observed"] = "Subscribed, but no SUBACK received: " .. sub_response
    helper:close()
    return output, stdnse.format_output(true, output)
  end

  -- 3) Listen briefly for PUBLISH messages so we can list which topics
  -- are actively in use, without keeping a long-lived connection open.
  local listen_time = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".listen-time")) or 3
  local end_time = nmap.clock_ms() + listen_time * 1000
  local topics_seen = {}
  local topic_list = {}
  while nmap.clock_ms() < end_time do
    local time_left = (end_time - nmap.clock_ms()) / 1000
    local status, msg = helper:receive({"PUBLISH"}, time_left)
    if not status then
      break
    end
    if not topics_seen[msg.topic] then
      topics_seen[msg.topic] = true
      table.insert(topic_list, msg.topic)
    end
  end

  helper:close()

  if #topic_list > 0 then
    output["Topics observed"] = table.concat(topic_list, ", ")
  else
    output["Topics observed"] = "None seen in " .. listen_time .. "s (broker may be idle right now)"
  end

  return output, stdnse.format_output(true, output)
end
