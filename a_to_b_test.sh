#!/bin/sh

####################### USER OPTIONS #######################
# Choose an appropriate speed test server here. Pick one geographically close to your location.
# flent-newark (East Coast US)
# netperf-west (West Coast US)
# netperf-eu (Denmark)
speedtest_server="flent-newark"
shell_out="/root/sqm-autorate-shell.log"
lua_out="/root/sqm-autorate-lua.log"
####################### END OF USER OPTIONS #######################

# We will use this later for better UX
service_stopped=false

echo ">>> Shell OWD vs Lua OWD Test <<<"
echo ""

####################### READY CHECKS #######################
echo "Checking to see if speedtest-netperf is installed."
if [ "$(opkg list-installed speedtest-netperf | wc -l)" = "0" ]; then
    echo "!!! Speedtest-netperf is missing from your system and is required for this test to function."
    read -p ">> Would you like to install speedtest-netperf now? (y/n) " install_choice
    install_choice=$(echo "$install_choice" | awk '{ print tolower($0) }')
    if [ "$install_choice" = "y" ] || [ "$install_choice" = "yes" ]; then
        opkg install speedtest-netperf || echo "!!! An error occurred while trying to install speedtest-netperf. Please try again."
        exit 1
    else
        # We have to bail out if we don't have speedtest-netperf on OpenWrt...
        echo "> You must install speedtest-netperf before using this test. Cannot continue. Exiting."
        exit 1
    fi
else
    echo "You have speedtest-netperf installed! Good job, human!"
fi

# Check if there are any other sqm-autorate processes running. If so kill them for now so
# we aren't battling TC control while monitoring performance of the line...
if [ "$(ps | grep sqm-autorate | grep -v grep -c)" -gt 0 ]; then
    # Try to gracefully stop the service if it exists...
    if [ -f /etc/init.d/sqm-autorate ]; then
        /etc/init.d/sqm-autorate stop
        service_stopped=true
    fi
    # Now forcefully kill (SIGKILL) anything left...
    count="$(ps | grep sqm-autorate | grep -v grep -c)"
    while [ "$count" -gt 0 ]; do
        ps | grep sqm-autorate | grep -v grep | awk '{print $1}' | xargs kill -9
        count="$(ps | grep sqm-autorate | grep -v grep -c)"
    done
fi

####################### SHELL TEST #######################
echo ""
echo "Beginning Shell OWD test now. This will take approximately 5-8 minutes..."
echo ""
# Start the shell autorate process in the background...
sh /root/sqm-autorate.sh >&$shell_out <&- &
test_pid=$!

# 60 second "idle" measurement for the log...
echo "> Beginning idle test..."
sleep 60

# Do a standard, controlled speedtest to chosen server...
echo "> Beginning download & upload speed test..."
speedtest-netperf.sh -H "$speedtest_server.bufferbloat.net"

# 60 second trailing "idle" measurement for the log. This should indicate how well things settle
# after the load drops back down...
echo "> Beginning cooldown idle test..."
sleep 60

# [SIG]KILL off this test...
kill -9 $test_pid

####################### INTERMISSION #######################
echo ""
echo "#######################################################################"

####################### LUA TEST #######################
echo ""
echo "Beginning Lua OWD test now. This will take approximately 5-8 minutes..."
echo ""
# Start the shell autorate process in the background...
lua /root/sqm-autorate.lua >&$lua_out <&- &
test_pid=$!

# 60 second "idle" measurement for the log...
echo "> Beginning idle test..."
sleep 60

# Do a standard, controlled speedtest to chosen server...
echo "> Beginning download & upload speed test..."
speedtest-netperf.sh -H "$speedtest_server.bufferbloat.net"

# 60 second trailing "idle" measurement for the log. This should indicate how well things settle
# after the load drops back down...
echo "> Beginning cooldown idle test..."
sleep 60

# [SIG]KILL off this test...
kill -9 $test_pid

####################### WRAP UP #######################
echo ""
echo "All done!"
# Restart the service for the user if we stopped it...
if [ $service_stopped = true ]; then
    /etc/init.d/sqm-autorate start
    echo ""
    echo " > Restarted your sqm-autorate service for you. <"
    echo ""
fi
echo "Your Shell output has been saved in $shell_out."
echo "Your Lua output has been saved in $lua_out."
echo "Please submit your outputs to this thread on the OpenWrt forum for analysis:"
echo "https://forum.openwrt.org/t/cake-w-adaptive-bandwidth/108848"
