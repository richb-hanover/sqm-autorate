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

return tunables
