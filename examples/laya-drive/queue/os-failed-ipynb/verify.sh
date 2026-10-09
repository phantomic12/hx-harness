f=/home/ubuntu/bench/fails
[ -f "$f/exp1/runs/trial.failed.ipynb" ] && [ -f "$f/exp2/train.failed.ipynb" ] && [ ! -e "$f/exp2/ok.ipynb" ]
