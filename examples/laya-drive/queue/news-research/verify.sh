#!/bin/bash
f=/home/ubuntu/news-writeup.txt
[ -f "$f" ] || exit 1
[ "$(stat -c%s "$f")" -ge 150 ] || exit 1
grep -qiE 'NEWS DIGEST|HEADLINE|pts|http|comment' "$f" || exit 1
exit 0
