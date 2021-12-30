local receiver = {}

local math = require "math"
local tunables = require "./tunables"
local utility = require "./utility"

local socket = require "posix.sys.socket"
local vstruct = require "vstruct"

local udp_port = 62222

local reflector_type = utility.get_config_setting("sqm-autorate", "network[0]", "reflector_type") or
                           tunables.reflector_type
local reflector_array_v4 = tunables.reflector_array_v4
local reflector_array_v6 = tunables.reflector_array_v6

local bit
if utility.is_module_available("bit") then
    bit = require "bit"
elseif utility.is_module_available("bit32") then
    bit = require "bit32"
end

-- Random seed
local nows, nowns = utility.get_current_time()
math.randomseed(nowns)

function receiver.receive_icmp_pkt(sock, pkt_id)
    utility.logger(utility.loglevel.TRACE, "Entered receive_icmp_pkt() with value: " .. pkt_id)

    -- Read ICMP TS reply
    local data, sa = socket.recvfrom(sock, 100) -- An IPv4 ICMP reply should be ~56bytes. This value may need tweaking.

    if data then
        local ip_start = string.byte(data, 1)
        local ip_ver = bit.rshift(ip_start, 4)
        local hdr_len = (ip_start - ip_ver * 16) * 4

        if (#data - hdr_len == 20) then
            if (string.byte(data, hdr_len + 1) == 14) then
                local ts_resp = vstruct.read("> 2*u1 3*u2 3*u4", string.sub(data, hdr_len + 1, #data))
                local time_after_midnight_ms = utility.get_time_after_midnight_ms()
                local src_pkt_id = ts_resp[4]
                local pos = utility.get_table_position(reflector_array_v4, sa.addr)

                -- A pos > 0 indicates the current sa.addr is a known member of the reflector array
                if (pos > 0 and src_pkt_id == pkt_id) then
                    local stats = {
                        reflector = sa.addr,
                        original_ts = ts_resp[6],
                        receive_ts = ts_resp[7],
                        transmit_ts = ts_resp[8],
                        rtt = time_after_midnight_ms - ts_resp[6],
                        uplink_time = ts_resp[7] - ts_resp[6],
                        downlink_time = time_after_midnight_ms - ts_resp[8]
                    }

                    utility.logger(utility.loglevel.DEBUG,
                        "Reflector IP: " .. stats.reflector .. "  |  Current time: " .. time_after_midnight_ms ..
                            "  |  TX at: " .. stats.original_ts .. "  |  RTT: " .. stats.rtt .. "  |  UL time: " ..
                            stats.uplink_time .. "  |  DL time: " .. stats.downlink_time)
                    utility.logger(utility.loglevel.TRACE, "Exiting receive_icmp_pkt() with stats return")

                    return stats
                end
            else
                utility.logger(utility.loglevel.TRACE, "Exiting receive_icmp_pkt() with nil return due to wrong type")
                return nil

            end
        else
            utility.logger(utility.loglevel.TRACE, "Exiting receive_icmp_pkt() with nil return due to wrong length")
            return nil
        end
    else
        utility.logger(utility.loglevel.TRACE, "Exiting receive_icmp_pkt() with nil return")

        return nil
    end
end

function receiver.receive_udp_pkt(sock, pkt_id)
    utility.logger(utility.loglevel.TRACE, "Entered receive_udp_pkt() with value: " .. pkt_id)

    -- Read UDP TS reply
    local data, sa = socket.recvfrom(sock, 100) -- An IPv4 ICMP reply should be ~56bytes. This value may need tweaking.

    if data then
        local ts_resp = vstruct.read("> 2*u1 3*u2 6*u4", data)
        print("HERE1")
        local time_after_midnight_ms = utility.get_time_after_midnight_ms()
        local src_pkt_id = ts_resp[4]
        local pos = utility.get_table_position(reflector_array_v4, sa.addr)
        print("HERE2")
        -- A pos > 0 indicates the current sa.addr is a known member of the reflector array
        if (pos > 0 and src_pkt_id == pkt_id) then
            local originate_ts = (ts_resp[6] % 86400 * 1000) + (math.floor(ts_resp[7] / 1000000))
            local receive_ts = (ts_resp[8] % 86400 * 1000) + (math.floor(ts_resp[9] / 1000000))
            local transmit_ts = (ts_resp[10] % 86400 * 1000) + (math.floor(ts_resp[11] / 1000000))

            local stats = {
                reflector = sa.addr,
                original_ts = originate_ts,
                receive_ts = receive_ts,
                transmit_ts = transmit_ts,
                rtt = time_after_midnight_ms - originate_ts,
                uplink_time = receive_ts - originate_ts,
                downlink_time = time_after_midnight_ms - transmit_ts
            }

            utility.logger(utility.loglevel.DEBUG,
                "Reflector IP: " .. stats.reflector .. "  |  Current time: " .. time_after_midnight_ms .. "  |  TX at: " ..
                    stats.original_ts .. "  |  RTT: " .. stats.rtt .. "  |  UL time: " .. stats.uplink_time ..
                    "  |  DL time: " .. stats.downlink_time)
            utility.logger(utility.loglevel.TRACE, "Exiting receive_udp_pkt() with stats return")

            return stats
        end
    else
        utility.logger(utility.loglevel.TRACE, "Exiting receive_udp_pkt() with nil return")

        return nil
    end
end

function receiver.ts_ping_receiver(sock, statistics_queue, pkt_id)
    utility.logger(utility.loglevel.TRACE, "Entered ts_ping_receiver() with value: " .. pkt_id)

    local receive_func = nil
    if reflector_type == "icmp" then
        receive_func = receiver.receive_icmp_pkt
    elseif reflector_type == "udp" then
        receive_func = receiver.receive_udp_pkt
    else
        utility.logger(utility.loglevel.ERROR, "Unknown packet type specified.")
    end

    while true do
        -- If we got stats, drop them onto the stats_queue for processing
        local stats = receive_func(sock, pkt_id)
        if stats then
            statistics_queue:send("stats", stats)
        end
    end
end

return receiver
