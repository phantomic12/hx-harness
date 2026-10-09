pkill -x kwrite 2>/dev/null; sleep 0.5
rm -f /home/ubuntu/devin-note.txt
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 QT_ACCESSIBILITY=1 kwrite >/dev/null 2>&1 &
for i in $(seq 60); do wmctrl -l | grep -qi 'KWrite' && break; sleep 0.25; done
sleep 0.6
