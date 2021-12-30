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
local pinger = lanes.require "./pinger"
local receiver = lanes.require "./receiver"
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

---------------------------- Begin Variables - External Settings ----------------------------
local enable_verbose_baseline_output = tunables.enable_verbose_baseline_output
local reflector_type = utility.get_config_setting("sqm-autorate", "network[0]", "reflector_type") or
                           tunables.reflector_type

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

---------------------------- Begin Conductor ----------------------------
local function conductor()
    print("Starting sqm-autorate.lua v" .. _VERSION)
    utility.logger(utility.loglevel.TRACE, "Entered conductor()")

    rate_controller.setup_bytes_paths()

    -- Random seed
    local nows, nowns = utility.get_current_time()
    math.randomseed(nowns)

    -- Set a packet ID
    local packet_id = cur_process_id + 32768

    -- Set initial TC values
    rate_controller.set_initial_cake_bandwidth()

    local threads = {
        pinger_thread = lanes.gen("*", {
            required = {"bit32", "posix.sys.socket", "posix.time", "vstruct"}
        }, pinger.ts_ping_sender)(sock, packet_id),
        receiver_thread = lanes.gen("*", {
            required = {"bit32", "posix.sys.socket", "posix.time", "vstruct"}
        }, receiver.ts_ping_receiver)(sock, stats_queue, packet_id),
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
