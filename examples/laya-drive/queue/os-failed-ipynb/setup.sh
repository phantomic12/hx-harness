pkill -x konsole 2>/dev/null; sleep 0.5
rm -rf /home/ubuntu/bench; mkdir -p /home/ubuntu/bench/nb/exp1/runs /home/ubuntu/bench/nb/exp2
printf '{}' > /home/ubuntu/bench/nb/exp1/runs/trial.failed.ipynb
printf '{}' > /home/ubuntu/bench/nb/exp2/train.failed.ipynb
printf '{}' > /home/ubuntu/bench/nb/exp2/ok.ipynb
QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 QT_ACCESSIBILITY=1 konsole --workdir /home/ubuntu/bench/nb >/dev/null 2>&1 &
for i in $(seq 60); do wmctrl -l | grep -qi 'Konsole' && break; sleep 0.25; done
sleep 0.6
