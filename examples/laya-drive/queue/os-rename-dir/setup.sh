pkill -x konsole 2>/dev/null; sleep 0.5
rm -rf /home/ubuntu/bench; mkdir -p /home/ubuntu/bench/todo_list_Jan_1
printf x > /home/ubuntu/bench/todo_list_Jan_1/item.txt
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 QT_ACCESSIBILITY=1 konsole --workdir /home/ubuntu/bench >/dev/null 2>&1 &
for i in $(seq 60); do wmctrl -l | grep -qi 'Konsole' && break; sleep 0.25; done
sleep 0.6
