#!/bin/bash
#SBATCH --job-name=vgcue-pilot
#SBATCH --partition=clip
#SBATCH --account=clip
#SBATCH --qos=high
#SBATCH --gres=gpu:rtxa6000:2
#SBATCH --nodes=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=04:00:00
#SBATCH --output=logs/pilot_%j.out
set -euo pipefail
cd "$SLURM_SUBMIT_DIR"
source jobs/common.sh
eval "$(conda shell.bash hook)"; conda activate "$CONDA_ENV"
start_vllm
URL="http://localhost:${PORT}/v1"
# Tiny real run first: fail fast if prompts or parsing break on real outputs.
python3 src/run_pilot.py --base-url "$URL" --model "$SERVED_NAME" --limit 3 \
  --out results/canary_judgments.jsonl
python3 - <<'PY'
import json
rows=[json.loads(l) for l in open("results/canary_judgments.jsonl")]
fails=sum(r["judgment"]=="parse_fail" for r in rows)
print(f"canary: {len(rows)} calls, {fails} parse failures")
assert rows and fails/len(rows) < 0.5, "canary parse-failure rate >= 50%: stopping"
PY
python3 src/run_pilot.py --base-url "$URL" --model "$SERVED_NAME" \
  --out results/judgments.jsonl
python3 src/analyze.py --in results/judgments.jsonl --out results
echo "PILOT DONE"
