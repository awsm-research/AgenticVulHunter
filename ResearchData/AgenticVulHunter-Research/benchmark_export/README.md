SCRBench Result Export

These two scripts convert Harbor job results into the 144-row JSONL format used by the SCRBench evaluator.

Export AgenticVulHunter Result

python benchmark_export/export_staged.py \
  --job jobs/sample_run \
  --threshold 0.6

The output is stored under:

output/sample_run-T0-60.jsonl

Export AgenticSCR Baseline

python benchmark_export/export_baseline.py \
  --job jobs/agenticscr-qwen-baseline-faithful-r2 \
  --output output/agenticscr-qwen-baseline-faithful-r2.jsonl

The output is stored at:

output/agenticscr-qwen-baseline-faithful-r2.jsonl