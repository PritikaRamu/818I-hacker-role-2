# Edit these once for your cluster. Sourced by the SLURM jobs.
export CONDA_ENV="/fs/clip-projects/rlab/pramu/miniconda3/envs/wavelength-eval"   # existing env: vllm 0.10.0, openai, matplotlib (no wandb)
export MODEL_PATH="/fs/clip-scratch/pramu/models/Qwen2.5-Coder-32B-Instruct"   # pre-downloaded weights
export SERVED_NAME="qwen-coder-32b"
export PORT="${PORT:-8011}"
export HF_HUB_OFFLINE=1                                   # compute nodes may lack internet
export WANDB_MODE="${WANDB_MODE:-offline}"                # run `wandb sync` from the login node later

start_vllm() {
  vllm serve "$MODEL_PATH" --served-model-name "$SERVED_NAME" \
    --tensor-parallel-size 2 --dtype bfloat16 --max-model-len 8192 \
    --gpu-memory-utilization 0.90 --port "$PORT" > "logs/vllm_${SLURM_JOB_ID}.log" 2>&1 &
  VLLM_PID=$!
  trap 'kill $VLLM_PID 2>/dev/null' EXIT
  for i in $(seq 1 120); do                               # up to 20 min to load
    curl -sf "http://localhost:${PORT}/health" >/dev/null && return 0
    kill -0 $VLLM_PID 2>/dev/null || { echo "vLLM died; see logs/vllm_${SLURM_JOB_ID}.log"; return 1; }
    sleep 10
  done
  echo "vLLM did not become healthy"; return 1
}
