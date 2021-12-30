local pinger = {}
-- if setfenv then
--     setfenv(1, pinger) -- for 5.1
-- else
--     _ENV = pinger -- for 5.2
-- end

local math = require "math"
local tunables = require "./tunables"
local utility = require "./utility"

local socket = require "posix.sys.socket"
local vstruct = require "vstruct"

local udp_port = 62222

local tick_duration = tunables.tick_duration

local reflector_type = utility.get_config_setting("sqm-autorate", "network[0]", "reflector_type") or
                           tunables.reflector_type
local reflector_array_v4 = tunables.reflector_array_v4
local reflector_array_v6 = tunables.reflector_array_v6

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
    print(tick_duration, reflector_type)
    utility.logger(utility.loglevel.TRACE, "Entered ts_ping_sender() with values: " .. tick_duration .. " | " ..
        reflector_type .. " | " .. pkt_id)
    local ff = (tick_duration / #reflector_array_v4)
    local sleep_time_ns = math.floor((ff % 1) * 1e9)
    local sleep_time_s = math.floor(ff)
    local ping_func = nil

    if reflector_type == "icmp" then
        ping_func = pinger.send_icmp_pkt
    elseif reflector_type == "udp" then
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
