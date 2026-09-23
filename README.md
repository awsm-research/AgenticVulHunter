# AgenticVulHunter

This repository contains both the **AgenticVulHunter research data** and the **AgenticVulHunter tool**.

## Research

For the research setup and experiment details:

https://github.com/awsm-research/AgenticVulHunter/blob/main/ResearchData/AgenticVulHunter-Research/README.md

## Tool

For the standalone AgenticVulHunter tool:

https://github.com/awsm-research/AgenticVulHunter/blob/main/AgenticVulHunter/README.md

## Install AgenticVulHunter

The tool is available through PyPI.

### Step 1: Install

```bash
pipx install agenticvulhunter
```

### Step 2: Create setup file

```bash
agenticvulhunter init
```

Update `avh_setup.toml`:

```toml
[llm]
endpoint = "http://127.0.0.1:11435/v1"
api_key = ""
```

### Step 3: Run review

```bash
agenticvulhunter review
```

This uses the default validation threshold of `0.6`.

To use another threshold:

```bash
agenticvulhunter review 0.7
```
