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
local baseliner = lanes.require "./baseliner"
local rate_controller = lanes.require "./ratecontroller"

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

---------------------------- Begin Variables - External Settings ----------------------------
local enable_verbose_baseline_output = tunables.enable_verbose_baseline_output
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

---------------------------- Begin Internal Local Variables ----------------------------

local cur_process_id = posix.getpid()
if type(cur_process_id) == "table" then
    cur_process_id = cur_process_id["pid"]
end

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

local bit
if utility.is_module_available("bit") then
    bit = lanes.require "bit"
elseif utility.is_module_available("bit32") then
    bit = lanes.require "bit32"
else
    utility.logger(utility.loglevel.FATAL, "No bitwise module found")
    os.exit(1, true)
end

---------------------------- End Local Variables ----------------------------

---------------------------- Begin Local Functions ----------------------------

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

    rate_controller.setup_bytes_paths()

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
        baseliner_thread = lanes.gen("*", {
            required = {"bit32", "posix", "posix.time"}
        }, baseliner.baseline_calculator)(stats_queue, owd_data, enable_verbose_baseline_output),
        rate_controllerer_thread = lanes.gen("*", {
            required = {"bit32", "posix", "posix.time"}
        }, rate_controller.ratecontrol)(owd_data)
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
