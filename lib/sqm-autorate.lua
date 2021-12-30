#!/usr/bin/env lua

-- Automatically adjust bandwidth for CAKE in dependence on detected load
-- and OWD, as well as connection history.
--
-- Inspired by @moeller0 (OpenWrt forum)
-- Initial sh implementation by @Lynx (OpenWrt forum)
-- Lua version maintained by @Lochnair, @dlakelan, and @_FailSafe (OpenWrt forum)
--
-- ** Recommended style guide: https://github.com/luarocks/lua-style-guide **
local lanes = require"lanes".configure()

local utility = lanes.require "./utility"
local tunables = lanes.require "./tunables"

-- Try to load argparse if it's installed
local argparse = nil
if utility.is_module_available("argparse") then
    argparse = lanes.require "argparse"
end

local debug = lanes.require "debug"
local math = lanes.require "math"
local posix = lanes.require "posix"
local socket = lanes.require "posix.sys.socket"
local time = lanes.require "posix.time"
local vstruct = lanes.require "vstruct"

-- The stats_queue is intended to be a true FIFO queue.
-- The purpose of the queue is to hold the processed timestamp
-- packets that are returned to us and this holds them for OWD
-- processing.
local stats_queue = lanes.linda()

-- The owd_data construct is not intended to be used as a queue.
-- Instead, it is just a method for sharing the OWD tables between
-- multiple threads. Calls against this construct will be get()/set()
-- to reinforce the intent that this is not a queue. This holds two
-- separate tables which are owd_baseline and owd_recent.
local owd_data = lanes.linda()
owd_data:set("owd_baseline", {})
owd_data:set("owd_recent", {})

-- The versioning value for this script
local _VERSION = "0.0.1b2"

-- Set a default log level here, until we've got one from UCI
local use_loglevel = utility.loglevel.INFO

local bit = nil
if utility.is_module_available("bit") then
    bit = lanes.require "bit"
elseif utility.is_module_available("bit32") then
    bit = lanes.require "bit32"
else
    utility.logger(utility.loglevel.FATAL, "No bitwise module found")
    os.exit(1, true)
end

---------------------------- Begin Variables - External Settings ----------------------------
local base_ul_rate = utility.get_config_setting_as_num("sqm-autorate", "network[0]", "transmit_kbits_base") or
                         tunables.base_ul_rate
local base_dl_rate = utility.get_config_setting_as_num("sqm-autorate", "network[0]", "receive_kbits_base") or
                         tunables.base_dl_rate
local min_ul_rate = utility.get_config_setting_as_num("sqm-autorate", "network[0]", "transmit_kbits_min") or
                        tunables.min_ul_rate
local min_dl_rate = utility.get_config_setting_as_num("sqm-autorate", "network[0]", "receive_kbits_min") or
                        tunables.min_dl_rate
local stats_file = utility.get_config_setting("sqm-autorate", "output[0]", "stats_file") or tunables.stats_file
local speedhist_file = utility.get_config_setting("sqm-autorate", "output[0]", "speed_hist_file") or
                           tunables.speedhist_file
local histsize = utility.get_config_setting_as_num("sqm-autorate", "output[0]", "hist_size") or tunables.histsize
local enable_verbose_baseline_output = tunables.enable_verbose_baseline_output
local tick_duration = tunables.tick_duration
local min_change_interval = tunables.min_change_interval
local ul_if = utility.get_config_setting("sqm-autorate", "network[0]", "transmit_interface") or tunables.ul_if
local dl_if = utility.get_config_setting("sqm-autorate", "network[0]", "receive_interface") or tunables.dl_if
local reflector_type = utility.get_config_setting("sqm-autorate", "network[0]", "reflector_type") or
                           tunables.reflector_type
local max_delta_owd = tunables.max_delta_owd
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

---------------------------- Begin Internal Local Variables ----------------------------

local cur_process_id = posix.getpid()
if type(cur_process_id) == "table" then
    cur_process_id = cur_process_id["pid"]
end

-- Bandwidth file paths
local rx_bytes_path = nil
local tx_bytes_path = nil

-- Create a socket
local sock
if reflector_type == "icmp" then
    sock = assert(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP), "Failed to create socket")
elseif reflector_type == "udp" then
    sock = assert(socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP), "Failed to create socket")
else
    utility.logger(utility.loglevel.FATAL, "Unknown reflector type specified. Cannot continue.")
    os.exit(1, true)
end

socket.setsockopt(sock, socket.SOL_SOCKET, socket.SO_SNDTIMEO, 0, 500)

---------------------------- End Local Variables ----------------------------

---------------------------- Begin Local Functions ----------------------------

local function update_cake_bandwidth(iface, rate_in_kbit)
    print(iface, rate_in_kbit)
    local is_changed = false
    if (iface == dl_if and rate_in_kbit >= min_dl_rate) or (iface == ul_if and rate_in_kbit >= min_ul_rate) then
        os.execute(string.format("tc qdisc change root dev %s cake bandwidth %sKbit", iface, rate_in_kbit))
        is_changed = true
    end
    return is_changed
end

local function receive_icmp_pkt(pkt_id)
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

local function receive_udp_pkt(pkt_id)
    utility.logger(utility.loglevel.TRACE, "Entered receive_udp_pkt() with value: " .. pkt_id)

    -- Read UDP TS reply
    local data, sa = socket.recvfrom(sock, 100) -- An IPv4 ICMP reply should be ~56bytes. This value may need tweaking.

    if data then
        local ts_resp = vstruct.read("> 2*u1 3*u2 6*u4", data)

        local time_after_midnight_ms = utility.get_time_after_midnight_ms()
        local src_pkt_id = ts_resp[4]
        local pos = utility.get_table_position(reflector_array_v4, sa.addr)

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

local function ts_ping_receiver(pkt_id, pkt_type)
    utility.logger(utility.loglevel.TRACE, "Entered ts_ping_receiver() with value: " .. pkt_id)

    local receive_func = nil
    if pkt_type == "icmp" then
        receive_func = receive_icmp_pkt
    elseif pkt_type == "udp" then
        receive_func = receive_udp_pkt
    else
        utility.logger(utility.loglevel.ERROR, "Unknown packet type specified.")
    end

    while true do
        -- If we got stats, drop them onto the stats_queue for processing
        local stats = receive_func(pkt_id)
        if stats then
            stats_queue:send("stats", stats)
        end
    end
end

local function send_icmp_pkt(reflector, pkt_id)
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

local function send_udp_pkt(reflector, pkt_id)
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
        port = 62222
    })

    utility.logger(utility.loglevel.TRACE, "Exiting send_udp_pkt()")

    return ok
end

local function ts_ping_sender(pkt_type, pkt_id, freq)
    utility.logger(utility.loglevel.TRACE,
        "Entered ts_ping_sender() with values: " .. freq .. " | " .. pkt_type .. " | " .. pkt_id)
    local ff = (freq / #reflector_array_v4)
    local sleep_time_ns = math.floor((ff % 1) * 1e9)
    local sleep_time_s = math.floor(ff)
    local ping_func = nil

    if pkt_type == "icmp" then
        ping_func = send_icmp_pkt
    elseif pkt_type == "udp" then
        ping_func = send_udp_pkt
    else
        utility.logger(utility.loglevel.ERROR, "Unknown packet type specified.")
    end

    while true do
        for _, reflector in ipairs(reflector_array_v4) do
            ping_func(reflector, pkt_id)
            utility.nsleep(sleep_time_s, sleep_time_ns)
        end

    end

    utility.logger(utility.loglevel.TRACE, "Exiting ts_ping_sender()")
end

local function read_stats_file(file)
    file:seek("set", 0)
    local bytes = file:read()
    return bytes
end

local function ratecontrol()
    local sleep_time_ns = math.floor((min_change_interval % 1) * 1e9)
    local sleep_time_s = math.floor(min_change_interval)

    local start_s, start_ns = utility.get_current_time() -- first time we entered this loop, times will be relative to this seconds value to preserve precision
    local lastchg_s, lastchg_ns = utility.get_current_time()
    local lastchg_t = lastchg_s - start_s + lastchg_ns / 1e9
    local lastdump_t = lastchg_t - 310

    local cur_dl_rate = base_dl_rate
    local cur_ul_rate = base_ul_rate
    local rx_bytes_file = io.open(rx_bytes_path)
    local tx_bytes_file = io.open(tx_bytes_path)

    if not rx_bytes_file or not tx_bytes_file then
        utility.logger(utility.loglevel.FATAL,
            "Could not open stats file: '" .. rx_bytes_path .. "' or '" .. tx_bytes_path .. "'")
        os.exit(1, true)
        return nil
    end

    local prev_rx_bytes = read_stats_file(rx_bytes_file)
    local prev_tx_bytes = read_stats_file(tx_bytes_file)
    local t_prev_bytes = lastchg_t
    local t_cur_bytes = lastchg_t

    local safe_dl_rates = {}
    local safe_ul_rates = {}
    for i = 0, histsize - 1, 1 do
        safe_dl_rates[i] = (math.random() * 0.2 + 0.75) * (base_dl_rate)
        safe_ul_rates[i] = (math.random() * 0.2 + 0.75) * (base_ul_rate)
    end

    local nrate_up = 0
    local nrate_down = 0

    local csv_fd = io.open(stats_file, "w")
    local speeddump_fd = io.open(speedhist_file, "w")

    csv_fd:write("times,timens,rxload,txload,deltadelaydown,deltadelayup,dlrate,uprate\n")
    speeddump_fd:write("time,counter,upspeed,downspeed\n")

    while true do
        local now_s, now_ns = utility.get_current_time()
        now_s = now_s - start_s
        local now_t = now_s + now_ns / 1e9
        if now_t - lastchg_t > min_change_interval then
            -- if it's been long enough, and the stats indicate needing to change speeds
            -- change speeds here

            local owd_baseline = owd_data:get("owd_baseline")
            local owd_recent = owd_data:get("owd_recent")

            local min_up_del = 1 / 0
            local min_down_del = 1 / 0

            for k, val in pairs(owd_baseline) do
                min_up_del = math.min(min_up_del, owd_recent[k].up_ewma - val.up_ewma)
                min_down_del = math.min(min_down_del, owd_recent[k].down_ewma - val.down_ewma)

                utility.logger(utility.loglevel.INFO, "min_up_del: " .. min_up_del .. "  min_down_del: " .. min_down_del)
            end

            local cur_rx_bytes = read_stats_file(rx_bytes_file)
            local cur_tx_bytes = read_stats_file(tx_bytes_file)
            t_prev_bytes = t_cur_bytes
            t_cur_bytes = now_t

            local rx_load = (8 / 1000) * (cur_rx_bytes - prev_rx_bytes) / (t_cur_bytes - t_prev_bytes) / cur_dl_rate
            local tx_load = (8 / 1000) * (cur_tx_bytes - prev_tx_bytes) / (t_cur_bytes - t_prev_bytes) / cur_ul_rate
            prev_rx_bytes = cur_rx_bytes
            prev_tx_bytes = cur_tx_bytes
            local next_ul_rate = cur_ul_rate
            local next_dl_rate = cur_dl_rate

            if min_up_del < max_delta_owd and tx_load > .8 then
                safe_ul_rates[nrate_up] = math.floor(cur_ul_rate * tx_load)
                local maxul = utility.maximum(safe_ul_rates)
                next_ul_rate = cur_ul_rate * (1 + .1 * math.max(0, (1 - cur_ul_rate / maxul))) + 500
                nrate_up = nrate_up + 1
                nrate_up = nrate_up % histsize
            end
            if min_down_del < max_delta_owd and rx_load > .8 then
                safe_dl_rates[nrate_down] = math.floor(cur_dl_rate * rx_load)
                local maxdl = utility.maximum(safe_dl_rates)
                next_dl_rate = cur_dl_rate * (1 + .1 * math.max(0, (1 - cur_dl_rate / maxdl))) + 500
                nrate_down = nrate_down + 1
                nrate_down = nrate_down % histsize
            end

            if min_up_del > max_delta_owd then
                if #safe_ul_rates > 0 then
                    next_ul_rate = math.min(0.9 * cur_ul_rate * tx_load, safe_ul_rates[math.random(#safe_ul_rates) - 1])
                else
                    next_ul_rate = 0.9 * cur_ul_rate * tx_load
                end
            end
            if min_down_del > max_delta_owd then
                if #safe_dl_rates > 0 then
                    next_dl_rate = math.min(0.9 * cur_dl_rate * rx_load, safe_dl_rates[math.random(#safe_dl_rates) - 1])
                else
                    next_dl_rate = 0.9 * cur_dl_rate * rx_load
                end
            end

            next_ul_rate = math.floor(math.max(min_ul_rate, next_ul_rate))
            next_dl_rate = math.floor(math.max(min_dl_rate, next_dl_rate))

            -- TC modification
            if next_dl_rate ~= cur_dl_rate then
                update_cake_bandwidth(dl_if, next_dl_rate)
            end
            if next_ul_rate ~= cur_ul_rate then
                update_cake_bandwidth(ul_if, next_ul_rate)
            end

            cur_dl_rate = next_dl_rate
            cur_ul_rate = next_ul_rate

            utility.logger(utility.loglevel.DEBUG,
                string.format("%d,%d,%f,%f,%f,%f,%d,%d\n", lastchg_s, lastchg_ns, rx_load, tx_load, min_down_del,
                    min_up_del, cur_dl_rate, cur_ul_rate))

            lastchg_s, lastchg_ns = utility.get_current_time()

            -- output to log file before doing delta on the time
            csv_fd:write(string.format("%d,%d,%f,%f,%f,%f,%d,%d\n", lastchg_s, lastchg_ns, rx_load, tx_load,
                min_down_del, min_up_del, cur_dl_rate, cur_ul_rate))

            lastchg_s = lastchg_s - start_s
            lastchg_t = lastchg_s + lastchg_ns / 1e9
        end

        if now_t - lastdump_t > 300 then
            for i = 0, histsize - 1 do
                speeddump_fd:write(string.format("%f,%d,%f,%f\n", now_t, i, safe_ul_rates[i], safe_dl_rates[i]))
            end
            lastdump_t = now_t
        end

        utility.nsleep(sleep_time_s, sleep_time_ns)
    end
end

local function baseline_calculator()
    local slow_factor = .9
    local fast_factor = .2

    while true do
        local _, time_data = stats_queue:receive(nil, "stats")
        local owd_baseline = owd_data:get("owd_baseline")
        local owd_recent = owd_data:get("owd_recent")

        if time_data then
            if not owd_baseline[time_data.reflector] then
                owd_baseline[time_data.reflector] = {}
            end
            if not owd_recent[time_data.reflector] then
                owd_recent[time_data.reflector] = {}
            end

            if not owd_baseline[time_data.reflector].up_ewma then
                owd_baseline[time_data.reflector].up_ewma = time_data.uplink_time
            end
            if not owd_recent[time_data.reflector].up_ewma then
                owd_recent[time_data.reflector].up_ewma = time_data.uplink_time
            end
            if not owd_baseline[time_data.reflector].down_ewma then
                owd_baseline[time_data.reflector].down_ewma = time_data.downlink_time
            end
            if not owd_recent[time_data.reflector].down_ewma then
                owd_recent[time_data.reflector].down_ewma = time_data.downlink_time
            end

            owd_baseline[time_data.reflector].up_ewma = owd_baseline[time_data.reflector].up_ewma * slow_factor +
                                                            (1 - slow_factor) * time_data.uplink_time
            owd_recent[time_data.reflector].up_ewma = owd_recent[time_data.reflector].up_ewma * fast_factor +
                                                          (1 - fast_factor) * time_data.uplink_time
            owd_baseline[time_data.reflector].down_ewma = owd_baseline[time_data.reflector].down_ewma * slow_factor +
                                                              (1 - slow_factor) * time_data.downlink_time
            owd_recent[time_data.reflector].down_ewma = owd_recent[time_data.reflector].down_ewma * fast_factor +
                                                            (1 - fast_factor) * time_data.downlink_time

            -- when baseline is above the recent, set equal to recent, so we track down more quickly
            owd_baseline[time_data.reflector].up_ewma = math.min(owd_baseline[time_data.reflector].up_ewma,
                owd_recent[time_data.reflector].up_ewma)
            owd_baseline[time_data.reflector].down_ewma = math.min(owd_baseline[time_data.reflector].down_ewma,
                owd_recent[time_data.reflector].down_ewma)

            -- Set the values back into the shared tables
            owd_data:set("owd_baseline", owd_baseline)
            owd_data:set("owd_recent", owd_recent)

            if enable_verbose_baseline_output then
                for ref, val in pairs(owd_baseline) do
                    local up_ewma = utility.a_else_b(val.up_ewma, "?")
                    local down_ewma = utility.a_else_b(val.down_ewma, "?")
                    utility.logger(utility.loglevel.INFO, "Reflector " .. ref .. " up baseline = " .. up_ewma ..
                        " down baseline = " .. down_ewma)
                end

                for ref, val in pairs(owd_recent) do
                    local up_ewma = utility.a_else_b(val.up_ewma, "?")
                    local down_ewma = utility.a_else_b(val.down_ewma, "?")
                    utility.logger(utility.loglevel.INFO, "Reflector " .. ref .. " up baseline = " .. up_ewma ..
                        " down baseline = " .. down_ewma)
                end
            end
        end
    end
end
---------------------------- End Local Functions ----------------------------

---------------------------- Begin Conductor ----------------------------
local function conductor()
    print("Starting sqm-autorate.lua v" .. _VERSION)
    utility.logger(utility.loglevel.TRACE, "Entered conductor()")

    -- Figure out the interfaces in play here
    -- if ul_if == "" then
    --     ul_if = settings and settings:get("sqm", "@queue[0]", "interface")
    --     if not ul_if then
    --         utility.logger(utility.loglevel.FATAL, "Upload interface not found in SQM config and was not overriden. Cannot continue.")
    --         os.exit(1, true)
    --     end
    -- end

    -- if dl_if == "" then
    --     local fh = io.popen(string.format("tc -p filter show parent ffff: dev %s", ul_if))
    --     local tc_filter = fh:read("*a")
    --     fh:close()

    --     local ifb_name = string.match(tc_filter, "ifb[%a%d]+")
    --     if not ifb_name then
    --         local ifb_name = string.match(tc_filter, "veth[%a%d]+")
    --     end
    --     if not ifb_name then
    --         utility.logger(utility.loglevel.FATAL, string.format(
    --             "Download interface not found for upload interface %s and was not overriden. Cannot continue.", ul_if))
    --         os.exit(1, true)
    --     end

    --     dl_if = ifb_name
    -- end
    utility.logger(utility.loglevel.DEBUG, "Upload iface: " .. ul_if .. " | Download iface: " .. dl_if)

    -- Verify these are correct using "cat /sys/class/..."
    if dl_if:find("^ifb.+") or dl_if:find("^veth.+") then
        rx_bytes_path = "/sys/class/net/" .. dl_if .. "/statistics/tx_bytes"
    else
        rx_bytes_path = "/sys/class/net/" .. dl_if .. "/statistics/rx_bytes"
    end

    if ul_if:find("^ifb.+") or ul_if:find("^veth.+") then
        tx_bytes_path = "/sys/class/net/" .. ul_if .. "/statistics/rx_bytes"
    else
        tx_bytes_path = "/sys/class/net/" .. ul_if .. "/statistics/tx_bytes"
    end

    utility.logger(utility.loglevel.DEBUG, "rx_bytes_path: " .. rx_bytes_path)
    utility.logger(utility.loglevel.DEBUG, "tx_bytes_path: " .. tx_bytes_path)

    -- Test for existent stats files
    local test_file = io.open(rx_bytes_path)
    if not test_file then
        utility.logger(utility.loglevel.FATAL, "Could not open stats file: " .. rx_bytes_path)
        os.exit(1, true)
    end
    test_file:close()

    test_file = io.open(tx_bytes_path)
    if not test_file then
        utility.logger(utility.loglevel.FATAL, "Could not open stats file: " .. tx_bytes_path)
        os.exit(1, true)
    end
    test_file:close()

    -- Random seed
    local nows, nowns = utility.get_current_time()
    math.randomseed(nowns)

    -- Set a packet ID
    local packet_id = cur_process_id + 32768

    -- Set initial TC values
    update_cake_bandwidth(dl_if, base_dl_rate)
    update_cake_bandwidth(ul_if, base_ul_rate)

    local threads = {
        pinger = lanes.gen("*", {
            required = {"bit32", "posix.sys.socket", "posix.time", "vstruct"}
        }, ts_ping_sender)(reflector_type, packet_id, tick_duration),
        receiver = lanes.gen("*", {
            required = {"bit32", "posix.sys.socket", "posix.time", "vstruct"}
        }, ts_ping_receiver)(packet_id, reflector_type),
        baseliner = lanes.gen("*", {
            required = {"bit32", "posix", "posix.time"}
        }, baseline_calculator)(),
        regulator = lanes.gen("*", {
            required = {"bit32", "posix", "posix.time"}
        }, ratecontrol)()
    }
    local join_timeout = 0.5

    -- Start this whole thing in motion!
    while true do
        for name, thread in pairs(threads) do
            local _, err = thread:join(join_timeout)

            if err and err ~= "timeout" then
                print('Something went wrong in the ' .. name .. ' thread')
                print(err)
                exit(1)
            end
        end
    end
end
---------------------------- End Conductor Loop ----------------------------

if argparse then
    local parser = argparse("sqm-autorate.lua", "CAKE with Adaptive Bandwidth - 'autorate'",
        "For more info, please visit: https://github.com/Fail-Safe/sqm-autorate")

    parser:flag("-v --version", "Displays the SQM Autorate version.")
    local args = parser:parse()

    -- Print the version and then exit
    if args.version then
        print(_VERSION)
        os.exit(0, true)
    end
end

conductor() -- go!
