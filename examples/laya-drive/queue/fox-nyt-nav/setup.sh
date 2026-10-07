#!/bin/bash
# Containerized browser: firefox-esr in debian on the host's X11 + a11y bus —
# the window and its a11y tree appear on the desktop but the app is isolated.
export DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1000/bus"
pkill -x kwrite 2>/dev/null; pkill -x konsole 2>/dev/null; pkill -f 'chrome' 2>/dev/null
sleep 1
docker rm -f kasm-fox >/dev/null 2>&1
rm -rf /tmp/ffhome && mkdir -p /tmp/ffhome && chown 1000:1000 /tmp/ffhome
docker run -d --name kasm-fox --net=host --user 1000:1000 \
  --security-opt apparmor=unconfined \
  -e HOME=/tmp/ffhome -e DISPLAY=$DISPLAY \
  -e DBUS_SESSION_BUS_ADDRESS="unix:path=/home/ubuntu/.cache/at-spi/bus_0" \
  -e XAUTHORITY=/tmp/.docker.xauth \
  -e MOZ_DISABLE_CONTENT_SANDBOX=1 -e MOZ_DISABLE_GMP_SANDBOX=1 \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v /home/ubuntu/.cache/at-spi:/home/ubuntu/.cache/at-spi \
  -v "$HOME/.Xauthority":/tmp/.docker.xauth:ro \
  -v /tmp/ffhome:/tmp/ffhome \
  kasm-fox >/dev/null 2>&1
for i in $(seq 80); do wmctrl -l | grep -qi 'Firefox' && break; sleep 0.25; done
# a11y registration lags the window appearing — wait for real elements
for i in $(seq 80); do
  python3 /home/ubuntu/laya-work/apps/hx/src/atspi_sense.py --app firefox --max 5 2>/dev/null \
    | grep -q '"id": "e0"' && break
  sleep 0.25
done
sleep 1
wmctrl -a 'Mozilla Firefox' 2>/dev/null || wmctrl -a 'Firefox' 2>/dev/null
sleep 0.5
wmctrl -r 'Mozilla Firefox' -b add,maximized_vert,maximized_horz 2>/dev/null
sleep 0.8
exit 0
