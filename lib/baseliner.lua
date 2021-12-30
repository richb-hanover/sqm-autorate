local baseliner = {}

local math = require "math"
local utility = require "./utility"

function baseliner.baseline_calculator(statistics_queue, owd_data_struct, verbose_baseline_output)
    local slow_factor = .9
    local fast_factor = .2

    while true do
        local _, time_data = statistics_queue:receive(nil, "stats")
        local owd_baseline = owd_data_struct:get("owd_baseline")
        local owd_recent = owd_data_struct:get("owd_recent")

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
            owd_data_struct:set("owd_baseline", owd_baseline)
            owd_data_struct:set("owd_recent", owd_recent)

            if verbose_baseline_output then
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

return baseliner
