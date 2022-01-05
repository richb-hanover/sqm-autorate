#!/usr/bin/env lua

-- Automatically adjust bandwidth for CAKE in dependence on detected load
-- and OWD, as well as connection history.
--
-- Inspired by @moeller0 (OpenWrt forum)
-- Initial sh implementation by @Lynx (OpenWrt forum)
-- Lua version maintained by @Lochnair, @dlakelan, and @_FailSafe (OpenWrt forum)
--
-- ** Recommended style guide: https://github.com/luarocks/lua-style-guide **
--
-- The versioning value for this script
local _VERSION = "0.2.1"
--
-- Found this clever function here: https://stackoverflow.com/a/15434737
-- This function will assist in compatibility given differences between OpenWrt, Turris OS, etc.
local function is_module_available(name)
    if package.loaded[name] then
        return true
    else
        for _, searcher in ipairs(package.searchers or package.loaders) do
            local loader = searcher(name)
            if type(loader) == 'function' then
                package.preload[name] = loader
                return true
            end
        end
        return false
    end
end

local lanes = require"lanes".configure()

-- Try to load argparse if it's installed
local argparse = nil
if is_module_available("argparse") then
    argparse = lanes.require "argparse"
end

local math = lanes.require "math"
local posix = lanes.require "posix"
local socket = lanes.require "posix.sys.socket"
local time = lanes.require "posix.time"
local vstruct = lanes.require "vstruct"

-- The stats_queue is intended to be a true FIFO queue.
-- The purpose of the queue is to hold the processed timestamp packets that are
-- returned to us and this holds them for OWD processing.
local stats_queue = lanes.linda()

-- The owd_data construct is not intended to be used as a queue.
-- Instead, it is used as a method for sharing the OWD tables between multiple threads.
-- Calls against this construct will be get()/set() to reinforce the intent that this
-- is not a queue. This holds two separate tables which are baseline and recent.
local owd_data = lanes.linda()
owd_data:set("owd_tables", {
    baseline = {},
    recent = {}
})

-- The relfector_data construct is not intended to be used as a queue.
-- Instead, is is used as a method for sharing the reflector tables between multiple threads.
-- Calls against this construct will be get()/set() to reinforce the intent that this
-- is not a queue. This holds two separate tables which are peers and pool.
local reflector_data = lanes.linda()
reflector_data:set("reflector_tables", {
    peers = {},
    pool = {}
})

local loglevel = {
    TRACE = {
        level = 6,
        name = "TRACE"
    },
    DEBUG = {
        level = 5,
        name = "DEBUG"
    },
    INFO = {
        level = 4,
        name = "INFO"
    },
    WARN = {
        level = 3,
        name = "WARN"
    },
    ERROR = {
        level = 2,
        name = "ERROR"
    },
    FATAL = {
        level = 1,
        name = "FATAL"
    }
}

-- Set a default log level here, until we've got one from UCI
local use_loglevel = loglevel.INFO

-- Basic homegrown logger to keep us from having to import yet another module
local function logger(loglevel, message)
    if (loglevel.level <= use_loglevel.level) then
        local cur_date = os.date("%Y%m%dT%H:%M:%S")
        -- local cur_date = os.date("%c")
        local out_str = string.format("[%s - %s]: %s", loglevel.name, cur_date, message)
        print(out_str)
    end
end

local bit = nil
local bit_mod = nil
if is_module_available("bit") then
    bit = lanes.require "bit"
    bit_mod = "bit"
elseif is_module_available("bit32") then
    bit = lanes.require "bit32"
    bit_mod = "bit32"
else
    logger(loglevel.FATAL, "No bitwise module found")
    os.exit(1, true)
end

-- Figure out if we are running on OpenWrt here and load luci.model.uci if available...
local uci_lib = nil
local settings = nil
if is_module_available("luci.model.uci") then
    uci_lib = require("luci.model.uci")
    settings = uci_lib.cursor()
end

-- If we have luci-app-sqm installed, but it is disabled, this whole thing is moot. Let's bail early in that case.
if settings then
    local sqm_enabled = tonumber(settings:get("sqm", "@queue[0]", "enabled"), 10)
    if sqm_enabled == 0 then
        logger(loglevel.FATAL,
            "SQM is not enabled on this OpenWrt system. Please enable it before starting sqm-autorate.")
        os.exit(1, true)
    end
end

---------------------------- Begin Local Variables - External Settings ----------------------------
local base_ul_rate = settings and tonumber(settings:get("sqm-autorate", "@network[0]", "transmit_kbits_base"), 10) or
                         "<STEADY STATE UPLOAD>" -- steady state bandwidth for upload
local base_dl_rate = settings and tonumber(settings:get("sqm-autorate", "@network[0]", "receive_kbits_base"), 10) or
                         "<STEADY STATE DOWNLOAD>" -- steady state bandwidth for download

local min_ul_rate = settings and tonumber(settings:get("sqm-autorate", "@network[0]", "transmit_kbits_min"), 10) or
                        "<MIN UPLOAD RATE>" -- don't go below this many kbps
local min_dl_rate = settings and tonumber(settings:get("sqm-autorate", "@network[0]", "receive_kbits_min"), 10) or
                        "<MIN DOWNLOAD RATE>" -- don't go below this many kbps

local stats_file = settings and settings:get("sqm-autorate", "@output[0]", "stats_file") or "<STATS FILE NAME/PATH>"
local speedhist_file = settings and settings:get("sqm-autorate", "@output[0]", "speed_hist_file") or
                           "<HIST FILE NAME/PATH>"

local histsize = settings and tonumber(settings:get("sqm-autorate", "@output[0]", "hist_size"), 10) or "<HISTORY SIZE>"

use_loglevel = loglevel[string.upper(settings and settings:get("sqm-autorate", "@output[0]", "log_level") or "INFO")]

---------------------------- Begin Advanced User-Configurable Local Variables ----------------------------
local enable_verbose_baseline_output = false

local tick_duration = 0.5 -- Frequency in seconds
local min_change_interval = 0.5 -- don't change speeds unless this many seconds has passed since last change

-- Interface names: leave empty to use values from SQM config or place values here to override SQM config
local ul_if = settings and settings:get("sqm-autorate", "@network[0]", "transmit_interface") or
                  "<UPLOAD INTERFACE NAME>" -- upload interface
local dl_if = settings and settings:get("sqm-autorate", "@network[0]", "receive_interface") or
                  "<DOWNLOAD INTERFACE NAME>" -- download interface

local reflector_list_icmp = "/usr/lib/sqm-autorate/reflectors-icmp.csv"
local reflector_list_udp = "/usr/lib/sqm-autorate/reflectors-udp.csv"
local reflector_type = settings and settings:get("sqm-autorate", "@network[0]", "reflector_type") or nil

local max_delta_owd = 15 -- increase from baseline RTT for detection of bufferbloat

---------------------------- Begin Internal Local Variables ----------------------------

local cur_process_id = posix.getpid()
if type(cur_process_id) == "table" then
    cur_process_id = cur_process_id["pid"]
end

-- Number of reflector peers to use from the pool
local num_reflectors = 5

-- Time (in minutes) before re-selection of peers from the pool
local peer_reselection_time = 15

-- Bandwidth file paths
local rx_bytes_path = nil
local tx_bytes_path = nil

-- Create a socket
local sock
if reflector_type == "icmp" then
    sock = assert(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP), "Failed to create socket")
elseif reflector_type == "udp" then
    print("UDP support is not available at this time. Please set your 'reflector_type' setting to 'icmp'.")
    os.exit(1, true)

    -- Hold for later use
    -- sock = assert(socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP), "Failed to create socket")
else
    logger(loglevel.FATAL, "Unknown reflector type specified. Cannot continue.")
    os.exit(1, true)
end

socket.setsockopt(sock, socket.SOL_SOCKET, socket.SO_SNDTIMEO, 0, 500)

---------------------------- End Local Variables ----------------------------

---------------------------- Begin Local Functions ----------------------------

local function load_reflector_list(file_path, ip_version)
    ip_version = ip_version or "4"

    local reflector_file = io.open(file_path)
    if not reflector_file then
        logger(loglevel.FATAL, "Could not open reflector file: '" .. file_path)
        os.exit(1, true)
        return nil
    end

    local reflectors = {}
    local lines = reflector_file:lines()
    for line in lines do
        local tokens = {}
        for token in string.gmatch(line, "([^,]+)") do -- Split the line on commas
            tokens[#tokens + 1] = token
        end
        local ip = tokens[1]
        local vers = tokens[2]
        if ip_version == "46" or ip_version == "both" or ip_version == "all" then
            reflectors[#reflectors + 1] = ip
        elseif vers == ip_version then
            reflectors[#reflectors + 1] = ip
        end
    end
    return reflectors
end

local function baseline_reflector_list(tbl)
    for _, v in ipairs(tbl) do
        local rtt

    end
end

local function a_else_b(a, b)
    if a then
        return a
    else
        return b
    end
end

local function nsleep(s, ns)
    -- nanosleep requires integers
    local floor = math.floor
    time.nanosleep({
        tv_sec = floor(s),
        tv_nsec = floor(((s % 1.0) * 1e9) + ns)
    })
end

local function get_current_time()
    local time_s, time_ns = 0, 0
    local val1, val2 = time.clock_gettime(time.CLOCK_REALTIME)
    if type(val1) == "table" then
        time_s = val1.tv_sec
        time_ns = val1.tv_nsec
    else
        time_s = val1
        time_ns = val2
    end
    return time_s, time_ns
end

local function get_time_after_midnight_ms()
    local time_s, time_ns = get_current_time()
    return (time_s % 86400 * 1000) + (math.floor(time_ns / 1000000))
end

local function dec_to_hex(number, digits)
    local bit_mask = (bit.lshift(1, (digits * 4))) - 1
    local str_fmt = "%0" .. digits .. "X"
    return string.format(str_fmt, bit.band(number, bit_mask))
end

-- This exists because the "bit" version of bnot() differs from the "bit32" version
-- of bnot(). This mimics the behavior of the "bit32" version and will therefore be
-- used for both "bit" and "bit32" execution.
local function bnot(data)
    local MOD = 2 ^ 32
    return (-1 - data) % MOD
end

local function calculate_checksum(data)
    local checksum = 0
    for i = 1, #data - 1, 2 do
        checksum = checksum + (bit.lshift(string.byte(data, i), 8)) + string.byte(data, i + 1)
    end
    if bit.rshift(checksum, 16) then
        checksum = bit.band(checksum, 0xffff) + bit.rshift(checksum, 16)
    end
    return bnot(checksum)
end

local function get_table_position(tbl, item)
    for i, value in ipairs(tbl) do
        if value == item then
            return i
        end
    end
    return 0
end

local function get_table_len(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    return count
end

local function shuffle_table(tbl)
    -- Fisher-Yates shuffle
    local random = math.random
    for i = #tbl, 2, -1 do
        local j = random(i)
        tbl[i], tbl[j] = tbl[j], tbl[i]
    end
    return tbl
end

local function maximum(table)
    local max = math.max
    local m = -1 / 0
    for _, v in pairs(table) do
        m = max(v, m)
    end
    return m
end

local function update_cake_bandwidth(iface, rate_in_kbit)
    local is_changed = false
    if (iface == dl_if and rate_in_kbit >= min_dl_rate) or (iface == ul_if and rate_in_kbit >= min_ul_rate) then
        os.execute(string.format("tc qdisc change root dev %s cake bandwidth %sKbit", iface, rate_in_kbit))
        is_changed = true
    end
    return is_changed
end

local function receive_icmp_pkt(pkt_id)
    logger(loglevel.TRACE, "Entered receive_icmp_pkt() with value: " .. pkt_id)

    -- Read ICMP TS reply
    local data, sa = socket.recvfrom(sock, 100) -- An IPv4 ICMP reply should be ~56bytes. This value may need tweaking.

    if data then
        local ip_start = string.byte(data, 1)
        local ip_ver = bit.rshift(ip_start, 4)
        local hdr_len = (ip_start - ip_ver * 16) * 4

        if (#data - hdr_len == 20) then
            if (string.byte(data, hdr_len + 1) == 14) then
                local ts_resp = vstruct.read("> 2*u1 3*u2 3*u4", string.sub(data, hdr_len + 1, #data))
                local time_after_midnight_ms = get_time_after_midnight_ms()
                local secs, nsecs = get_current_time()
                local src_pkt_id = ts_resp[4]

                local reflector_tables = reflector_data:get("reflector_tables")
                local reflector_list = reflector_tables["peers"]
                if reflector_list then
                    local pos = get_table_position(reflector_list, sa.addr)

                    -- A pos > 0 indicates the current sa.addr is a known member of the reflector array
                    if (pos > 0 and src_pkt_id == pkt_id) then
                        local stats = {
                            reflector = sa.addr,
                            original_ts = ts_resp[6],
                            receive_ts = ts_resp[7],
                            transmit_ts = ts_resp[8],
                            rtt = time_after_midnight_ms - ts_resp[6],
                            uplink_time = ts_resp[7] - ts_resp[6],
                            downlink_time = time_after_midnight_ms - ts_resp[8],
                            last_receive_time_s = secs + nsecs / 1e9
                        }

                        logger(loglevel.DEBUG,
                            "Reflector IP: " .. stats.reflector .. "  |  Current time: " .. time_after_midnight_ms ..
                                "  |  TX at: " .. stats.original_ts .. "  |  RTT: " .. stats.rtt .. "  |  UL time: " ..
                                stats.uplink_time .. "  |  DL time: " .. stats.downlink_time)
                        logger(loglevel.TRACE, "Exiting receive_icmp_pkt() with stats return")

                        return stats
                    end
                end
            else
                logger(loglevel.TRACE, "Exiting receive_icmp_pkt() with nil return due to wrong type")
                return nil

            end
        else
            logger(loglevel.TRACE, "Exiting receive_icmp_pkt() with nil return due to wrong length")
            return nil
        end
    else
        logger(loglevel.TRACE, "Exiting receive_icmp_pkt() with nil return")

        return nil
    end
end

local function receive_udp_pkt(pkt_id)
    logger(loglevel.TRACE, "Entered receive_udp_pkt() with value: " .. pkt_id)

    local floor = math.floor

    -- Read UDP TS reply
    local data, sa = socket.recvfrom(sock, 100) -- An IPv4 ICMP reply should be ~56bytes. This value may need tweaking.

    if data then
        local ts_resp = vstruct.read("> 2*u1 3*u2 6*u4", data)

        local time_after_midnight_ms = get_time_after_midnight_ms()
        local secs, nsecs = get_current_time()
        local src_pkt_id = ts_resp[4]
        local reflector_tables = reflector_data:get("reflector_tables")
        local reflector_list = reflector_tables["peers"]
        local pos = get_table_position(reflector_list, sa.addr)

        -- A pos > 0 indicates the current sa.addr is a known member of the reflector array
        if (pos > 0 and src_pkt_id == pkt_id) then
            local originate_ts = (ts_resp[6] % 86400 * 1000) + (floor(ts_resp[7] / 1000000))
            local receive_ts = (ts_resp[8] % 86400 * 1000) + (floor(ts_resp[9] / 1000000))
            local transmit_ts = (ts_resp[10] % 86400 * 1000) + (floor(ts_resp[11] / 1000000))

            local stats = {
                reflector = sa.addr,
                original_ts = originate_ts,
                receive_ts = receive_ts,
                transmit_ts = transmit_ts,
                rtt = time_after_midnight_ms - originate_ts,
                uplink_time = receive_ts - originate_ts,
                downlink_time = time_after_midnight_ms - transmit_ts,
                last_receive_time_s = secs + nsecs / 1e9
            }

            logger(loglevel.DEBUG,
                "Reflector IP: " .. stats.reflector .. "  |  Current time: " .. time_after_midnight_ms .. "  |  TX at: " ..
                    stats.original_ts .. "  |  RTT: " .. stats.rtt .. "  |  UL time: " .. stats.uplink_time ..
                    "  |  DL time: " .. stats.downlink_time)
            logger(loglevel.TRACE, "Exiting receive_udp_pkt() with stats return")

            return stats
        end
    else
        logger(loglevel.TRACE, "Exiting receive_udp_pkt() with nil return")

        return nil
    end
end

local function ts_ping_receiver(pkt_id, pkt_type)
    logger(loglevel.TRACE, "Entered ts_ping_receiver() with value: " .. pkt_id)

    local receive_func = nil
    if pkt_type == "icmp" then
        receive_func = receive_icmp_pkt
    elseif pkt_type == "udp" then
        receive_func = receive_udp_pkt
    else
        logger(loglevel.ERROR, "Unknown packet type specified.")
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

    logger(loglevel.TRACE, "Entered send_icmp_pkt() with values: " .. reflector .. " | " .. pkt_id)

    -- Create a raw ICMP timestamp request message
    local time_after_midnight_ms = get_time_after_midnight_ms()
    local ts_req = vstruct.write("> 2*u1 3*u2 3*u4", {13, 0, 0, pkt_id, 0, time_after_midnight_ms, 0, 0})
    local ts_req = vstruct.write("> 2*u1 3*u2 3*u4",
        {13, 0, calculate_checksum(ts_req), pkt_id, 0, time_after_midnight_ms, 0, 0})

    -- Send ICMP TS request
    local ok = socket.sendto(sock, ts_req, {
        family = socket.AF_INET,
        addr = reflector,
        port = 0
    })

    logger(loglevel.TRACE, "Exiting send_icmp_pkt()")

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

    logger(loglevel.TRACE, "Entered send_udp_pkt() with values: " .. reflector .. " | " .. pkt_id)

    -- Create a raw ICMP timestamp request message
    local time, time_ns = get_current_time()
    local ts_req = vstruct.write("> 2*u1 3*u2 6*u4", {13, 0, 0, pkt_id, 0, time, time_ns, 0, 0, 0, 0})
    local ts_req = vstruct.write("> 2*u1 3*u2 6*u4",
        {13, 0, calculate_checksum(ts_req), pkt_id, 0, time, time_ns, 0, 0, 0, 0})

    -- Send ICMP TS request
    local ok = socket.sendto(sock, ts_req, {
        family = socket.AF_INET,
        addr = reflector,
        port = 62222
    })

    logger(loglevel.TRACE, "Exiting send_udp_pkt()")

    return ok
end

local function ts_ping_sender(pkt_type, pkt_id, freq)
    logger(loglevel.TRACE, "Entered ts_ping_sender() with values: " .. freq .. " | " .. pkt_type .. " | " .. pkt_id)

    local floor = math.floor

    local reflector_tables = reflector_data:get("reflector_tables")
    local reflector_list = reflector_tables["peers"]
    local ff = (freq / #reflector_list)
    local sleep_time_ns = floor((ff % 1) * 1e9)
    local sleep_time_s = floor(ff)

    local ping_func = nil
    if pkt_type == "icmp" then
        ping_func = send_icmp_pkt
    elseif pkt_type == "udp" then
        ping_func = send_udp_pkt
    else
        logger(loglevel.ERROR, "Unknown packet type specified.")
    end

    while true do
        local reflector_tables = reflector_data:get("reflector_tables")
        local reflector_list = reflector_tables["peers"]

        if reflector_list then
            -- Update sleep time based on number of peers
            ff = (freq / #reflector_list)
            sleep_time_ns = floor((ff % 1) * 1e9)
            sleep_time_s = floor(ff)

            for _, reflector in ipairs(reflector_list) do
                ping_func(reflector, pkt_id)
                nsleep(sleep_time_s, sleep_time_ns)
            end
        end
    end

    logger(loglevel.TRACE, "Exiting ts_ping_sender()")
end

local function read_stats_file(file)
    file:seek("set", 0)
    local bytes = file:read()
    return bytes
end

local function ratecontrol()
    local floor = math.floor
    local max = math.max
    local min = math.min
    local random = math.random

    local sleep_time_ns = floor((min_change_interval % 1) * 1e9)
    local sleep_time_s = floor(min_change_interval)

    local start_s, start_ns = get_current_time() -- first time we entered this loop, times will be relative to this seconds value to preserve precision
    local lastchg_s, lastchg_ns = get_current_time()
    local lastchg_t = lastchg_s - start_s + lastchg_ns / 1e9
    local lastdump_t = lastchg_t - 310

    local cur_dl_rate = base_dl_rate
    local cur_ul_rate = base_ul_rate
    local rx_bytes_file = io.open(rx_bytes_path)
    local tx_bytes_file = io.open(tx_bytes_path)

    if not rx_bytes_file or not tx_bytes_file then
        logger(loglevel.FATAL, "Could not open stats file: '" .. rx_bytes_path .. "' or '" .. tx_bytes_path .. "'")
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
        safe_dl_rates[i] = (random() * 0.2 + 0.75) * (base_dl_rate)
        safe_ul_rates[i] = (random() * 0.2 + 0.75) * (base_ul_rate)
    end

    local nrate_up = 0
    local nrate_down = 0

    local csv_fd = io.open(stats_file, "w")
    local speeddump_fd = io.open(speedhist_file, "w")

    csv_fd:write("times,timens,rxload,txload,deltadelaydown,deltadelayup,dlrate,uprate\n")
    speeddump_fd:write("time,counter,upspeed,downspeed\n")

    while true do
        local now_s, now_ns = get_current_time()
        local now_abstime = now_s + now_ns / 1e9
        now_s = now_s - start_s
        local now_t = now_s + now_ns / 1e9
        if now_t - lastchg_t > min_change_interval then
            -- if it's been long enough, and the stats indicate needing to change speeds
            -- change speeds here

            local owd_tables = owd_data:get("owd_tables")
            local owd_baseline = owd_tables["baseline"]
            local owd_recent = owd_tables["recent"]

            local reflector_tables = reflector_data:get("reflector_tables")
            local reflector_list = reflector_tables["peers"]

            -- If we have no reflector peers to iterate over, don't attempt any rate changes.
            -- This will occur under normal operation when the reflector peers table is updated.
            if reflector_list then
                local up_del = {}
                local down_del = {}
                for _, reflector_ip in ipairs(reflector_list) do
                    -- only consider this data if it's less than 2 * tick_duration seconds old
                    if owd_recent[reflector_ip] ~= nil and owd_baseline[reflector_ip] ~= nil and
                        owd_recent[reflector_ip].last_receive_time_s ~= nil and
                        owd_recent[reflector_ip].last_receive_time_s > now_abstime - 2 * tick_duration then
                        table.insert(up_del, owd_recent[reflector_ip].up_ewma - owd_baseline[reflector_ip].up_ewma)
                        table.insert(down_del, owd_recent[reflector_ip].down_ewma - owd_baseline[reflector_ip].down_ewma)

                        logger(loglevel.INFO, "reflector: " .. reflector_ip .. " delay: " .. up_del[#up_del] ..
                            "  down_del: " .. down_del[#down_del])
                    end
                end
                table.sort(up_del)
                table.sort(down_del)

                local up_del_stat = a_else_b(up_del[3], up_del[1])
                local down_del_stat = a_else_b(down_del[3], down_del[1])

                local cur_rx_bytes = read_stats_file(rx_bytes_file)
                local cur_tx_bytes = read_stats_file(tx_bytes_file)

                if cur_rx_bytes and cur_tx_bytes then
                    if up_del_stat and down_del_stat then
                        t_prev_bytes = t_cur_bytes
                        t_cur_bytes = now_t

                        local rx_load = (8 / 1000) * (cur_rx_bytes - prev_rx_bytes) / (t_cur_bytes - t_prev_bytes) /
                                            cur_dl_rate
                        local tx_load = (8 / 1000) * (cur_tx_bytes - prev_tx_bytes) / (t_cur_bytes - t_prev_bytes) /
                                            cur_ul_rate
                        prev_rx_bytes = cur_rx_bytes
                        prev_tx_bytes = cur_tx_bytes
                        local next_ul_rate = cur_ul_rate
                        local next_dl_rate = cur_dl_rate
                        logger(loglevel.INFO, "up_del_stat " .. up_del_stat .. " down_del_stat " .. down_del_stat)
                        if up_del_stat and up_del_stat < max_delta_owd and tx_load > .8 then
                            safe_ul_rates[nrate_up] = floor(cur_ul_rate * tx_load)
                            local max_ul = maximum(safe_ul_rates)
                            next_ul_rate = cur_ul_rate * (1 + .1 * max(0, (1 - cur_ul_rate / max_ul))) +
                                               (base_ul_rate * 0.03)
                            nrate_up = nrate_up + 1
                            nrate_up = nrate_up % histsize
                        end
                        if down_del_stat and down_del_stat < max_delta_owd and rx_load > .8 then
                            safe_dl_rates[nrate_down] = floor(cur_dl_rate * rx_load)
                            local max_dl = maximum(safe_dl_rates)
                            next_dl_rate = cur_dl_rate * (1 + .1 * max(0, (1 - cur_dl_rate / max_dl))) +
                                               (base_dl_rate * 0.03)
                            nrate_down = nrate_down + 1
                            nrate_down = nrate_down % histsize
                        end

                        if up_del_stat > max_delta_owd then
                            if #safe_ul_rates > 0 then
                                next_ul_rate = min(0.9 * cur_ul_rate * tx_load,
                                    safe_ul_rates[random(#safe_ul_rates) - 1])
                            else
                                next_ul_rate = 0.9 * cur_ul_rate * tx_load
                            end
                        end
                        if down_del_stat > max_delta_owd then
                            if #safe_dl_rates > 0 then
                                next_dl_rate = min(0.9 * cur_dl_rate * rx_load,
                                    safe_dl_rates[random(#safe_dl_rates) - 1])
                            else
                                next_dl_rate = 0.9 * cur_dl_rate * rx_load
                            end
                        end
                        logger(loglevel.INFO, "next_ul_rate " .. next_ul_rate .. " next_dl_rate " .. next_dl_rate)
                        next_ul_rate = floor(max(min_ul_rate, next_ul_rate))
                        next_dl_rate = floor(max(min_dl_rate, next_dl_rate))

                        -- TC modification
                        if next_dl_rate ~= cur_dl_rate then
                            update_cake_bandwidth(dl_if, next_dl_rate)
                        end
                        if next_ul_rate ~= cur_ul_rate then
                            update_cake_bandwidth(ul_if, next_ul_rate)
                        end

                        cur_dl_rate = next_dl_rate
                        cur_ul_rate = next_ul_rate

                        logger(loglevel.DEBUG,
                            string.format("%d,%d,%f,%f,%f,%f,%d,%d\n", lastchg_s, lastchg_ns, rx_load, tx_load,
                                down_del_stat, up_del_stat, cur_dl_rate, cur_ul_rate))

                        lastchg_s, lastchg_ns = get_current_time()

                        -- output to log file before doing delta on the time
                        csv_fd:write(string.format("%d,%d,%f,%f,%f,%f,%d,%d\n", lastchg_s, lastchg_ns, rx_load, tx_load,
                            down_del_stat, up_del_stat, cur_dl_rate, cur_ul_rate))

                        lastchg_s = lastchg_s - start_s
                        lastchg_t = lastchg_s + lastchg_ns / 1e9
                    else
                        logger(loglevel.WARN,
                            "Either up_del_stat or down_del_stat are bad. Skipping rate control algorithm... up_del_stat: " ..
                                up_del_stat .. " | down_del_stat: " .. down_del_stat)
                    end
                else
                    logger(loglevel.WARN, "One or both stats files could not be read. Skipping rate control algorithm.")
                end
            end
        end

        if now_t - lastdump_t > 300 then
            for i = 0, histsize - 1 do
                speeddump_fd:write(string.format("%f,%d,%f,%f\n", now_t, i, safe_ul_rates[i], safe_dl_rates[i]))
            end
            lastdump_t = now_t
        end

        nsleep(sleep_time_s, sleep_time_ns)
    end
end

local function baseline_calculator()
    local min = math.min

    local slow_factor = .9
    local fast_factor = .2

    while true do
        local _, time_data = stats_queue:receive(nil, "stats")
        local owd_tables = owd_data:get("owd_tables")
        local owd_baseline = owd_tables["baseline"]
        local owd_recent = owd_tables["recent"]

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

            owd_baseline[time_data.reflector].last_receive_time_s = time_data.last_receive_time_s
            owd_recent[time_data.reflector].last_receive_time_s = time_data.last_receive_time_s
            owd_baseline[time_data.reflector].up_ewma = owd_baseline[time_data.reflector].up_ewma * slow_factor +
                                                            (1 - slow_factor) * time_data.uplink_time
            owd_recent[time_data.reflector].up_ewma = owd_recent[time_data.reflector].up_ewma * fast_factor +
                                                          (1 - fast_factor) * time_data.uplink_time
            owd_baseline[time_data.reflector].down_ewma = owd_baseline[time_data.reflector].down_ewma * slow_factor +
                                                              (1 - slow_factor) * time_data.downlink_time
            owd_recent[time_data.reflector].down_ewma = owd_recent[time_data.reflector].down_ewma * fast_factor +
                                                            (1 - fast_factor) * time_data.downlink_time

            -- when baseline is above the recent, set equal to recent, so we track down more quickly
            owd_baseline[time_data.reflector].up_ewma = min(owd_baseline[time_data.reflector].up_ewma,
                owd_recent[time_data.reflector].up_ewma)
            owd_baseline[time_data.reflector].down_ewma = min(owd_baseline[time_data.reflector].down_ewma,
                owd_recent[time_data.reflector].down_ewma)

            -- Set the values back into the shared tables
            owd_data:set("owd_tables", {
                baseline = owd_baseline,
                recent = owd_recent
            })

            if enable_verbose_baseline_output then
                for ref, val in pairs(owd_baseline) do
                    local up_ewma = a_else_b(val.up_ewma, "?")
                    local down_ewma = a_else_b(val.down_ewma, "?")
                    logger(loglevel.INFO,
                        "Reflector " .. ref .. " up baseline = " .. up_ewma .. " down baseline = " .. down_ewma)
                end

                for ref, val in pairs(owd_recent) do
                    local up_ewma = a_else_b(val.up_ewma, "?")
                    local down_ewma = a_else_b(val.down_ewma, "?")
                    logger(loglevel.INFO, "Reflector " .. ref .. "recent up baseline = " .. up_ewma ..
                        "recent down baseline = " .. down_ewma)
                end
            end
        end
    end
end

local function rtt_compare(a, b)
    return a[2] < b[2] -- Index 2 is the RTT value
end

local function reflector_peer_selector()
    local floor = math.floor
    local pi = math.pi
    local random = math.random

    local selector_sleep_time_ns = 0
    local selector_sleep_time_s = peer_reselection_time * 60

    local baseline_sleep_time_ns = floor(((tick_duration * pi) % 1) * 1e9)
    local baseline_sleep_time_s = floor(tick_duration * pi)

    -- Initial wait of several seconds to allow some OWD data to build up
    nsleep(baseline_sleep_time_s, baseline_sleep_time_ns)

    while true do
        local peerhash = {} -- a hash table of next peers, to ensure uniqueness
        local next_peers = {} -- an array of next peers
        local reflector_tables = reflector_data:get("reflector_tables")
        local reflector_pool = reflector_tables["pool"]

        for k, v in pairs(reflector_tables["peers"]) do -- include all current peers
            peerhash[v] = 1
        end
        for i = 1, 20, 1 do -- add 20 at random, but
            local nextcandidate = reflector_pool[random(#reflector_pool)]
            peerhash[nextcandidate] = 1
        end
        for k, v in pairs(peerhash) do
            next_peers[#next_peers + 1] = k
        end
        -- Put all the pool members back into the peers for some re-baselining...
        reflector_data:set("reflector_tables", {
            peers = next_peers,
            pool = reflector_pool
        })

        -- Wait for several seconds to allow all reflectors to be re-baselined
        nsleep(baseline_sleep_time_s, baseline_sleep_time_ns)

        local candidates = {}

        local owd_tables = owd_data:get("owd_tables")
        local owd_recent = owd_tables["recent"]

        for i, peer in ipairs(next_peers) do
            if owd_recent[peer] then
                local up_del = owd_recent[peer].up_ewma
                local down_del = owd_recent[peer].down_ewma
                local rtt = up_del + down_del
                candidates[#candidates + 1] = {peer, rtt}
                logger(loglevel.INFO, "Candidate reflector: " .. peer .. " RTT: " .. rtt)
            else
                logger(loglevel.INFO, "No data found from candidate reflector: " .. peer .. " - skipping")
            end
        end

        -- Sort the candidates table now by ascending RTT
        table.sort(candidates, rtt_compare)

        -- Now we will just limit the candidates down to 2 * num_reflectors
        local num_reflectors = num_reflectors
        local candidate_pool_num = 2 * num_reflectors
        if candidate_pool_num < #candidates then
            for i = candidate_pool_num + 1, #candidates, 1 do
                candidates[i] = nil
            end
        end
        for i, v in ipairs(candidates) do
            logger(loglevel.INFO, "Fastest candidate " .. i .. ": " .. v[1] .. " - RTT: " .. v[2])
        end

        -- Shuffle the deck so we avoid overwhelming good reflectors
        candidates = shuffle_table(candidates)

        local new_peers = {}
        if #candidates < num_reflectors then
            num_reflectors = #candidates
        end
        for i = 1, num_reflectors, 1 do
            new_peers[#new_peers + 1] = candidates[i][1]
        end

        for _, v in ipairs(new_peers) do
            logger(loglevel.INFO, "New selected peer: " .. v)
        end

        reflector_data:set("reflector_tables", {
            peers = new_peers,
            pool = reflector_pool
        })

        nsleep(selector_sleep_time_s, selector_sleep_time_ns)
    end
end
---------------------------- End Local Functions ----------------------------

---------------------------- Begin Conductor ----------------------------
local function conductor()
    print("Starting sqm-autorate.lua v" .. _VERSION)
    logger(loglevel.TRACE, "Entered conductor()")

    -- Random seed
    local nows, nowns = get_current_time()
    math.randomseed(nowns)

    -- Figure out the interfaces in play here
    -- if ul_if == "" then
    --     ul_if = settings and settings:get("sqm", "@queue[0]", "interface")
    --     if not ul_if then
    --         logger(loglevel.FATAL, "Upload interface not found in SQM config and was not overriden. Cannot continue.")
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
    --         logger(loglevel.FATAL, string.format(
    --             "Download interface not found for upload interface %s and was not overriden. Cannot continue.", ul_if))
    --         os.exit(1, true)
    --     end

    --     dl_if = ifb_name
    -- end
    logger(loglevel.DEBUG, "Upload iface: " .. ul_if .. " | Download iface: " .. dl_if)

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

    logger(loglevel.DEBUG, "rx_bytes_path: " .. rx_bytes_path)
    logger(loglevel.DEBUG, "tx_bytes_path: " .. tx_bytes_path)

    -- Test for existent stats files
    local test_file = io.open(rx_bytes_path)
    if not test_file then
        -- Let's wait and retry a few times before failing hard. These files typically
        -- take some time to be generated following a reboot.
        local retries = 12
        local retry_time = 5 -- secs
        for i = 1, retries, 1 do
            logger(loglevel.WARN,
                "Rx stats file not yet available. Will retry again in " .. retry_time .. " seconds. (Attempt " .. i ..
                    " of " .. retries .. ")")
            nsleep(retry_time, 0)
            test_file = io.open(rx_bytes_path)
            if test_file then
                break
            end
        end

        if not test_file then
            logger(loglevel.FATAL, "Could not open stats file: " .. rx_bytes_path)
            os.exit(1, true)
        end
    end
    test_file:close()
    logger(loglevel.INFO, "Rx stats file found! Continuing...")

    test_file = io.open(tx_bytes_path)
    if not test_file then
        -- Let's wait and retry a few times before failing hard. These files typically
        -- take some time to be generated following a reboot.
        local retries = 12
        local retry_time = 5 -- secs
        for i = 1, retries, 1 do
            logger(loglevel.WARN,
                "Tx stats file not yet available. Will retry again in " .. retry_time .. " seconds. (Attempt " .. i ..
                    " of " .. retries .. ")")
            nsleep(retry_time, 0)
            test_file = io.open(tx_bytes_path)
            if test_file then
                break
            end
        end

        if not test_file then
            logger(loglevel.FATAL, "Could not open stats file: " .. tx_bytes_path)
            os.exit(1, true)
        end
    end
    test_file:close()
    logger(loglevel.INFO, "Tx stats file found! Continuing...")

    -- Load up the reflectors temp table
    local tmp_reflectors = {}
    if reflector_type == "icmp" then
        tmp_reflectors = load_reflector_list(reflector_list_icmp, "4")
    elseif reflector_type == "udp" then
        tmp_reflectors = load_reflector_list(reflector_list_udp, "4")
    else
        logger(loglevel.FATAL, "Unknown reflector type specified: " .. reflector_type)
        os.exit(1, true)
    end

    logger(loglevel.INFO, "Reflector Pool Size: " .. #tmp_reflectors)

    -- Load up the reflectors shared tables
    reflector_data:set("reflector_tables", {
        peers = tmp_reflectors,
        pool = tmp_reflectors
    })

    -- Set a packet ID
    local packet_id = cur_process_id + 32768

    -- Set initial TC values
    update_cake_bandwidth(dl_if, base_dl_rate)
    update_cake_bandwidth(ul_if, base_ul_rate)

    local threads = {
        receiver = lanes.gen("*", {
            required = {bit_mod, "posix.sys.socket", "posix.time", "vstruct"}
        }, ts_ping_receiver)(packet_id, reflector_type),
        baseliner = lanes.gen("*", {
            required = {"posix", "posix.time"}
        }, baseline_calculator)(),
        regulator = lanes.gen("*", {
            required = {"posix", "posix.time"}
        }, ratecontrol)(),
        pinger = lanes.gen("*", {
            required = {bit_mod, "posix.sys.socket", "posix.time", "vstruct"}
        }, ts_ping_sender)(reflector_type, packet_id, tick_duration),
        selector = lanes.gen("*", {
            required = {"posix", "posix.time"}
        }, reflector_peer_selector)()
    }
    local join_timeout = 0.5

    -- Start this whole thing in motion!
    while true do
        for name, thread in pairs(threads) do
            local _, err = thread:join(join_timeout)

            if err and err ~= "timeout" then
                print('Something went wrong in the ' .. name .. ' thread')
                print(err)
                os.exit(1, true)
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
