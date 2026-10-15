-- coap-security-check.nse
--
-- We "require" (import) Nmap's own libraries instead of writing the raw
-- UDP/CoAP byte encoding ourselves. coap.lua already knows how to build and
-- parse CoAP packets (RFC 7252) -- reusing it is the same pattern every
-- built-in NSE script follows (e.g. ftp-anon.nse requires "ftp"). The
-- original part of THIS script is the security logic below: nothing in
-- Nmap's own scripts flags plaintext transport or sensitive resource names.
local coap = require "coap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes a CoAP endpoint's resource-discovery path (/.well-known/core),
lists every resource it exposes, and flags two security concerns:
1) The device is reachable over plaintext CoAP (UDP/5683) instead of
   encrypted CoAPs over DTLS (UDP/5684).
2) Any discovered resource path looks administrative or sensitive
   (e.g. contains "admin", "config", "password") and is exposed with
   no authentication at all.

This is discovery/enumeration only: one GET request is sent, nothing
is written, brute-forced, or exploited.
]]

---
-- @usage nmap -sU -p 5683 --script coap-security-check <target>
-- @args coap-security-check.uri Resource-discovery path to GET,
--       defaults to /.well-known/core
-- @output
-- PORT     STATE SERVICE
-- 5683/udp open  coap
-- | coap-security-check:
-- |   Transport: [RISK] Plaintext CoAP on port 5683 -- no DTLS encryption. Secure CoAPs normally runs on UDP/5684.
-- |   Discovered resources:
-- |     /sensors/temp: [READABLE]
-- |_    /admin/config: [RISK] sensitive-looking path, no authentication required

author = "Harsha Vardan M Sakamuri"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Only run against hosts/ports that look like CoAP, over UDP.
portrule = shortport.port_or_service(5683, "coap", "udp")

-- Keywords that suggest a resource path should not be handed out to an
-- unauthenticated client. This is a simple, explainable heuristic, not a
-- claim that the resource is provably compromised.
local SENSITIVE_KEYWORDS = {"admin", "config", "password", "cred", "secret", "key"}

-- Returns true if `path` contains any of the sensitive keywords above.
local function looks_sensitive(path)
  local lower_path = path:lower()
  for _, word in ipairs(SENSITIVE_KEYWORDS) do
    if lower_path:find(word, 1, true) then
      return true
    end
  end
  return false
end

action = function(host, port)
  local output = stdnse.output_table()

  -- 1) Flag the transport itself. Because portrule only matches port 5683,
  -- every host we reach here is, by definition, using unencrypted CoAP.
  output["Transport"] = "[RISK] Plaintext CoAP on port " .. port.number ..
    " -- no DTLS encryption. Secure CoAPs normally runs on UDP/5684."

  -- 2) Ask the device to list its own resources via .well-known/core.
  local uri = stdnse.get_script_args(SCRIPT_NAME .. ".uri") or "/.well-known/core"
  local helper = coap.Helper:new(host, port)
  local status, response = helper:connect({["uri"] = uri})
  if not status then
    -- No valid CoAP reply -> probably not a CoAP service, stay silent.
    return nil
  end
  if response.code ~= "content" then
    output.ERROR = ("Device replied with code '%s' instead of 'content'."):format(response.code)
    return output, output.ERROR
  end

  -- 3) coap.lua already parsed the link-format payload for us into a
  -- list of {name, parameters} tables (it does this automatically for
  -- any single-block response with a recognised content format).
  local links = response.payload
  if type(links) ~= "table" then
    output["Discovered resources"] = "Could not parse resource list (raw payload returned)."
    return output, stdnse.format_output(true, output)
  end

  -- 4) Tag every discovered path as [READABLE] or [RISK], matching the
  -- keyword heuristic above.
  local resources = stdnse.output_table()
  for _, link in ipairs(links) do
    if looks_sensitive(link.name) then
      resources[link.name] = "[RISK] sensitive-looking path, no authentication required"
    else
      resources[link.name] = "[READABLE]"
    end
  end
  output["Discovered resources"] = resources

  return output, stdnse.format_output(true, output)
end
