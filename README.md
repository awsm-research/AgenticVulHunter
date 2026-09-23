AgenticVulHunter

This repository contains both the AgenticVulHunter Data and Tool

Research

For the research :

https://github.com/awsm-research/AgenticVulHunter/blob/main/ResearchData/AgenticVulHunter-Research/README.md


Tool

For the standalone AgenticVulHunter tool:

https://github.com/awsm-research/AgenticVulHunter/blob/main/AgenticVulHunter/README.md



Install AgenticVulHunter

The tool is available through PyPI.

Using pipx:

pipx install agenticvulhunter

or using pip:

pip install agenticvulhunter



Check the installed version:

agenticvulhunter --version

Setup

Create the AVH setup file:

agenticvulhunter init

This creates:

[llm]
endpoint = "http://127.0.0.1:11435/v1"
api_key = ""

The endpoint and API key can also be provided through AVH environment variables.

Run a review

agenticvulhunter review (This uses the default validation threshold of 0.6.)

To use another threshold:

agenticvulhunter review 0.7

Pipeline

AgenticVulHunter runs the following four-stage pipeline:

Git diff
   ↓
Stage 1: Candidate localisation
   ↓
Stage 2: Context enrichment
   ↓
Stage 3: CWE hypothesis generation
   ↓
Stage 4: Vulnerability validation
   ↓
Review comments above the threshold

The research implementation and the standalone tool are kept in the same repository, but they are separated so the research experiments do not need to be included in the lightweight runtime tool.
