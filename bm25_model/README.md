# Existing BM25 / SAST retriever

This directory is the BM25 component supplied with the original AgenticBugHunter project. The core `agenticbughunter` Python package does **not** implement BM25 ranking; Stage 3 calls a configured HTTP endpoint.

To run this bundled service separately:

```bash
cd bm25_model
python -m pip install -r requirements.txt
python sast_retriever_server.py --host 127.0.0.1 --port 5056
```

Then configure the project plugin with:

```toml
[bm25]
endpoint = "http://localhost:5056/predict"
```

or set `SAST_RETRIEVER_URL`.
