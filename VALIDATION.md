# Release validation

Validated on 2026-09-06 in the provided Linux workspace with Python 3.12.13.

| Check | Result |
|---|---|
| Standard-library unittest suite | 40 tests passed |
| Existing configuration/UI and BM25 tests | Passed |
| Provider request/response and failure tests | Passed offline |
| Five-stage pipeline with real Git/BM25 and scripted model | Passed |
| Divergent commit history and worktree cleanup | Passed |
| Existing push-hook stdin preservation and restoration | Passed |
| Wheel build without network or dependency installation | Passed |
| Install wheel into separate target directory | Passed |
| Import installed package and CLI help | Passed |
| Bundled assets after wheel installation | 314 rules, 132 CWE knowledge entries |
| Live provider API calls | Not run; no model credentials used |
| Full research benchmark / accuracy evaluation | Not run |

The fixture model is deterministic and validates software contracts, not actual
vulnerability detection. These results do not establish precision or recall.
The package contains a prebuilt wheel at `dist/agenticbughunter-0.6.0-py3-none-any.whl`.

Reproduce the tests from the source root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```
