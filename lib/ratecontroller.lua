local ratecontroller = {}

local math = require "math"
local tunables = require "./tunables"
local utility = require "./utility"

-- Bandwidth file paths
local rx_bytes_path = nil
local tx_bytes_path = nil

local min_change_interval = tunables.min_change_interval
local max_delta_owd = tunables.max_delta_owd

local base_ul_rate = utility.get_config_setting_as_num("sqm-autorate", "network[0]", "transmit_kbits_base") or
                         tunables.base_ul_rate
local base_dl_rate = utility.get_config_setting_as_num("sqm-autorate", "network[0]", "receive_kbits_base") or
                         tunables.base_dl_rate
local min_ul_rate = utility.get_config_setting_as_num("sqm-autorate", "network[0]", "transmit_kbits_min") or
                        tunables.min_ul_rate
local min_dl_rate = utility.get_config_setting_as_num("sqm-autorate", "network[0]", "receive_kbits_min") or
                        tunables.min_dl_rate
local ul_if = utility.get_config_setting("sqm-autorate", "network[0]", "transmit_interface") or tunables.ul_if
local dl_if = utility.get_config_setting("sqm-autorate", "network[0]", "receive_interface") or tunables.dl_if
local stats_file = utility.get_config_setting("sqm-autorate", "output[0]", "stats_file") or tunables.stats_file
local speedhist_file = utility.get_config_setting("sqm-autorate", "output[0]", "speed_hist_file") or
                           tunables.speedhist_file
local histsize = utility.get_config_setting_as_num("sqm-autorate", "output[0]", "hist_size") or tunables.histsize

function ratecontroller.setup_bytes_paths()
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
    -- utility.logger(utility.loglevel.DEBUG, "Upload iface: " .. ul_if .. " | Download iface: " .. dl_if)

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
end

function ratecontroller.update_cake_bandwidth(iface, rate_in_kbit)
    print(iface, rate_in_kbit)
    local is_changed = false
    if (iface == dl_if and rate_in_kbit >= min_dl_rate) or (iface == ul_if and rate_in_kbit >= min_ul_rate) then
        os.execute(string.format("tc qdisc change root dev %s cake bandwidth %sKbit", iface, rate_in_kbit))
        is_changed = true
    end
    return is_changed
end

function ratecontroller.set_initial_cake_bandwidth()
    ratecontroller.update_cake_bandwidth(dl_if, base_dl_rate)
    ratecontroller.update_cake_bandwidth(ul_if, base_ul_rate)
end

function ratecontroller.read_stats_file(file)
    file:seek("set", 0)
    local bytes = file:read()
    return bytes
end

function ratecontroller.ratecontrol(owd_data_struct)
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

    local prev_rx_bytes = ratecontroller.read_stats_file(rx_bytes_file)
    local prev_tx_bytes = ratecontroller.read_stats_file(tx_bytes_file)
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

            local owd_baseline = owd_data_struct:get("owd_baseline")
            local owd_recent = owd_data_struct:get("owd_recent")

            local min_up_del = 1 / 0
            local min_down_del = 1 / 0

            for k, val in pairs(owd_baseline) do
                min_up_del = math.min(min_up_del, owd_recent[k].up_ewma - val.up_ewma)
                min_down_del = math.min(min_down_del, owd_recent[k].down_ewma - val.down_ewma)

                utility.logger(utility.loglevel.INFO, "min_up_del: " .. min_up_del .. "  min_down_del: " .. min_down_del)
            end

            local cur_rx_bytes = ratecontroller.read_stats_file(rx_bytes_file)
            local cur_tx_bytes = ratecontroller.read_stats_file(tx_bytes_file)
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
                ratecontroller.update_cake_bandwidth(dl_if, next_dl_rate)
            end
            if next_ul_rate ~= cur_ul_rate then
                ratecontroller.update_cake_bandwidth(ul_if, next_ul_rate)
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

return ratecontroller
