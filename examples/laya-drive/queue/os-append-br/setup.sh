pkill -x kwrite 2>/dev/null; sleep 0.5
rm -rf /home/ubuntu/bench; mkdir -p /home/ubuntu/bench
printf 'alpha\nbeta\ngamma\n' > /home/ubuntu/bench/br-doc.txt
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 QT_ACCESSIBILITY=1 kwrite /home/ubuntu/bench/br-doc.txt >/dev/null 2>&1 &
for i in $(seq 60); do wmctrl -l | grep -qi 'KWrite' && break; sleep 0.25; done
sleep 0.6
