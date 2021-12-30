local tunables = {}

---------------------------- Begin Base User-Configurable Variables ----------------------------
tunables.base_ul_rate = "" -- steady state bandwidth for upload
tunables.base_dl_rate = "" -- steady state bandwidth for download

tunables.min_ul_rate = "" -- don't go below this many kbps
tunables.min_dl_rate = "" -- don't go below this many kbps

tunables.stats_file = ""
tunables.speedhist_file = ""

tunables.histsize = ""

tunables.use_loglevel = ""

---------------------------- Begin Advanced User-Configurable Variables ----------------------------
tunables.enable_verbose_baseline_output = false

tunables.max_delta_owd = 15 -- increase from baseline RTT for detection of bufferbloat

tunables.tick_duration = 0.5 -- Frequency in seconds
tunables.min_change_interval = 0.5 -- don't change speeds unless this many seconds has passed since last change

-- Interface names: leave empty to use values from SQM config or place values here to override SQM config
tunables.ul_if = "" -- upload interface
tunables.dl_if = "" -- download interface

tunables.reflector_type = "icmp"

tunables.reflector_array_v4 = {}
tunables.reflector_array_v6 = {}

if tunables.reflector_type == "icmp" then
    tunables.reflector_array_v4 = {"46.227.200.54", "46.227.200.55", "194.242.2.2", "194.242.2.3", "149.112.112.10",
                                   "149.112.112.11", "149.112.112.112", "193.19.108.2", "193.19.108.3", "9.9.9.9",
                                   "9.9.9.10", "9.9.9.11"}
else
    tunables.reflector_array_v4 = {"65.21.108.153", "5.161.66.148", "216.128.149.82", "108.61.220.16", "185.243.217.26",
                                   "185.175.56.188", "176.126.70.119"}
    tunables.reflector_array_v6 = {"2a01:4f9:c010:5469::1", "2a01:4ff:f0:2194::1",
                                   "2001:19f0:5c01:1bb6:5400:03ff:febe:3fae", "2001:19f0:6001:3de9:5400:03ff:febe:3f8e",
                                   "2a03:94e0:ffff:185:243:217:0:26", "2a0d:5600:30:46::2", "2a00:1a28:1157:3ef::2"}
end

return tunables
