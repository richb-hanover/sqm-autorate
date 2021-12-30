local pinger = {}

local math = require "math"
local tunables = require "./tunables"
local utility = require "./utility"

local socket = require "posix.sys.socket"
local vstruct = require "vstruct"

local udp_port = 62222

local tick_duration = tunables.tick_duration

local reflector_type = utility.get_config_setting("sqm-autorate", "network[0]", "reflector_type") or
                           tunables.reflector_type
local reflector_array_v4 = {}
local reflector_array_v6 = {}

if reflector_type == "icmp" then
    reflector_array_v4 = {"46.227.200.54", "46.227.200.55", "194.242.2.2", "194.242.2.3", "149.112.112.10",
                          "149.112.112.11", "149.112.112.112", "193.19.108.2", "193.19.108.3", "9.9.9.9", "9.9.9.10",
                          "9.9.9.11"}
else
    reflector_array_v4 = {"65.21.108.153", "5.161.66.148", "216.128.149.82", "108.61.220.16", "185.243.217.26",
                          "185.175.56.188", "176.126.70.119"}
    reflector_array_v6 = {"2a01:4f9:c010:5469::1", "2a01:4ff:f0:2194::1", "2001:19f0:5c01:1bb6:5400:03ff:febe:3fae",
                          "2001:19f0:6001:3de9:5400:03ff:febe:3f8e", "2a03:94e0:ffff:185:243:217:0:26",
                          "2a0d:5600:30:46::2", "2a00:1a28:1157:3ef::2"}
end

function pinger.send_icmp_pkt(sock, reflector, pkt_id)
    -- ICMP timestamp header
    -- Type - 1 byte
    -- Code - 1 byte:
    -- Checksum - 2 bytes
    -- Identifier - 2 bytes
    -- Sequence number - 2 bytes
    -- Original timestamp - 4 bytes
    -- Received timestamp - 4 bytes
    -- Transmit timestamp - 4 bytes

    utility.logger(utility.loglevel.TRACE, "Entered send_icmp_pkt() with values: " .. reflector .. " | " .. pkt_id)

    -- Create a raw ICMP timestamp request message
    local time_after_midnight_ms = utility.get_time_after_midnight_ms()
    local ts_req = vstruct.write("> 2*u1 3*u2 3*u4", {13, 0, 0, pkt_id, 0, time_after_midnight_ms, 0, 0})
    local ts_req = vstruct.write("> 2*u1 3*u2 3*u4",
        {13, 0, utility.calculate_checksum(ts_req), pkt_id, 0, time_after_midnight_ms, 0, 0})

    -- Send ICMP TS request
    local ok = socket.sendto(sock, ts_req, {
        family = socket.AF_INET,
        addr = reflector,
        port = 0
    })

    utility.logger(utility.loglevel.TRACE, "Exiting send_icmp_pkt()")

    return ok
end

function pinger.send_udp_pkt(sock, reflector, pkt_id)
    -- Custom UDP timestamp header
    -- Type - 1 byte
    -- Code - 1 byte:
    -- Checksum - 2 bytes
    -- Identifier - 2 bytes
    -- Sequence number - 2 bytes
    -- Original timestamp - 4 bytes
    -- Original timestamp (nanoseconds) - 4 bytes
    -- Received timestamp - 4 bytes
    -- Received timestamp (nanoseconds) - 4 bytes
    -- Transmit timestamp - 4 bytes
    -- Transmit timestamp (nanoseconds) - 4 bytes

    utility.logger(utility.loglevel.TRACE, "Entered send_udp_pkt() with values: " .. reflector .. " | " .. pkt_id)

    -- Create a raw ICMP timestamp request message
    local time, time_ns = utility.get_current_time()
    local ts_req = vstruct.write("> 2*u1 3*u2 6*u4", {13, 0, 0, pkt_id, 0, time, time_ns, 0, 0, 0, 0})
    local ts_req = vstruct.write("> 2*u1 3*u2 6*u4",
        {13, 0, utility.calculate_checksum(ts_req), pkt_id, 0, time, time_ns, 0, 0, 0, 0})

    -- Send ICMP TS request
    local ok = socket.sendto(sock, ts_req, {
        family = socket.AF_INET,
        addr = reflector,
        port = udp_port
    })

    utility.logger(utility.loglevel.TRACE, "Exiting send_udp_pkt()")

    return ok
end

function pinger.ts_ping_sender(sock, pkt_id)
    print(pinger.tick_duration, pinger.reflector_type)
    utility.logger(utility.loglevel.TRACE, "Entered ts_ping_sender() with values: " .. pinger.tick_duration .. " | " ..
        pinger.reflector_type .. " | " .. pkt_id)
    local ff = (pinger.tick_duration / #reflector_array_v4)
    local sleep_time_ns = math.floor((ff % 1) * 1e9)
    local sleep_time_s = math.floor(ff)
    local ping_func = nil

    if pinger.reflector_type == "icmp" then
        ping_func = pinger.send_icmp_pkt
    elseif pinger.reflector_type == "udp" then
        ping_func = pinger.send_udp_pkt
    else
        utility.logger(utility.loglevel.ERROR, "Unknown packet type specified.")
    end

    while true do
        for _, reflector in ipairs(reflector_array_v4) do
            ping_func(sock, reflector, pkt_id)
            utility.nsleep(sleep_time_s, sleep_time_ns)
        end

    end

    utility.logger(utility.loglevel.TRACE, "Exiting ts_ping_sender()")
end

return pinger
