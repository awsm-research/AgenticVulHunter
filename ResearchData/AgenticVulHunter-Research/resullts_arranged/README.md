Results Arranged

This folder stores the arranged outputs from AgenticVulHunter and baseline experiments.

Folder Structure

results_arranged/
├── all_result_in_jsonl/
├── leader_board_logs/
├── logs_jobs/
└── README.md

Main Folders

all_result_in_jsonl/ contains the exported JSONL result files used for evaluation in paper.

leader_board_logs/ contains evaluation and leaderboard-related logs.

logs_jobs/ contains logs and files collected from the Harbor experiment jobs.

The exported JSONL files are generated from the Harbor job results using the scripts inside:

benchmark_export/

These arranged results are kept separately from the main AgenticVulHunter implementation so the experiment outputs are easier to manage and reproduce.