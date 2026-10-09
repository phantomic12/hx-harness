FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    firefox-esr fonts-liberation dbus-x11 at-spi2-core libatk1.0-0 libatk-bridge2.0-0 \
    && rm -rf /var/lib/apt/lists/*
ENV GTK_MODULES=gail:atk-bridge
ENV GNOME_ACCESSIBILITY=1
CMD ["firefox-esr", "--new-instance", "--width", "1280", "--height", "800"]
