f=/home/ubuntu/bench/old_files.txt
[ -f "$f" ] && grep -q "ancient.txt" "$f" && grep -q "old2.log" "$f" && ! grep -q "fresh.txt" "$f"
