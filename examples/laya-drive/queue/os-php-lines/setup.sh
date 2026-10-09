pkill -x konsole 2>/dev/null; sleep 0.5
rm -rf /home/ubuntu/bench; mkdir -p /home/ubuntu/bench/php/lib
printf 'a\nb\nc\n' > /home/ubuntu/bench/php/index.php
printf 'x\n' > /home/ubuntu/bench/php/lib/util.php
printf 'n\n' > /home/ubuntu/bench/php/notes.txt
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 QT_ACCESSIBILITY=1 konsole --workdir /home/ubuntu/bench >/dev/null 2>&1 &
for i in $(seq 60); do wmctrl -l | grep -qi 'Konsole' && break; sleep 0.25; done
sleep 0.6
