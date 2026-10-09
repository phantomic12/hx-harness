f=/home/ubuntu/bench/php_lines.txt
[ -f "$f" ] && grep -q "index.php" "$f" && grep -q "util.php" "$f"
