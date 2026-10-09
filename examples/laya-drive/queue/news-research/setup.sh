#!/bin/bash
export DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
pkill -f 'chrome' 2>/dev/null
wmctrl -c 'KWrite' 2>/dev/null; pkill -x kwrite 2>/dev/null; pkill -x konsole 2>/dev/null
sleep 0.6
rm -f /tmp/hn.json /tmp/art.json /tmp/topid /tmp/digest.txt
echo > /home/ubuntu/news-writeup.txt
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 QT_ACCESSIBILITY=1 kwrite /home/ubuntu/news-writeup.txt >/dev/null 2>&1 &
for i in $(seq 60); do wmctrl -l | grep -qi 'news-writeup' && break; sleep 0.25; done
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 QT_ACCESSIBILITY=1 konsole --workdir /home/ubuntu >/dev/null 2>&1 &
for i in $(seq 60); do wmctrl -l | grep -qi 'Konsole' && break; sleep 0.25; done
wmctrl -a 'Konsole' 2>/dev/null
sleep 0.8
exit 0
