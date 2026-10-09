# kasm-fox — Kasm-style containerized browser for `hx drive`

A Firefox-ESR container that shows up on the host desktop like a local app —
its window renders on the host X server and its accessibility tree registers
on the host AT-SPI bus, so `hx drive` senses and clicks it exactly like a
local browser while the app stays isolated.

## Build

```sh
docker build -t kasm-fox examples/laya-drive/kasm-fox
```

## Run (what `queue/fox-nyt-nav/setup.sh` does)

```sh
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
  kasm-fox
```

Notes:

- The a11y bus is **not** the session bus. Find it with
  `xprop -root AT_SPI_BUS` — on this box it is
  `unix:path=/home/ubuntu/.cache/at-spi/bus_0`. Pointing the container's
  `DBUS_SESSION_BUS_ADDRESS` at the real session bus gets AccessDenied on
  `org.a11y.Bus` (AppArmor-mediated); mounting the a11y socket dir and
  pointing straight at `bus_0` bypasses that.
- `--user 1000:1000` + a writable `HOME` — firefox-esr refuses to run as
  root and needs a profile dir.
- `MOZ_DISABLE_*_SANDBOX=1` — the container's namespace setup otherwise
  breaks content/GMP sandbox creation and the renderer never appears.
