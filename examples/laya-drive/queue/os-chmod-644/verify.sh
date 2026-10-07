[ "$(stat -c %a /home/ubuntu/bench/perms/a.txt)" = 644 ] && \
[ "$(stat -c %a /home/ubuntu/bench/perms/b.txt)" = 644 ] && \
[ "$(stat -c %a /home/ubuntu/bench/perms/sub/c.sh)" = 644 ] && \
[ -d /home/ubuntu/bench/perms/sub ]
