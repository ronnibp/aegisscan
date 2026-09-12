# Contributing to AegisScan

Thanks for helping improve AegisScan!

## Development setup

```bash
git clone https://github.com/ronnibp/aegisscan.git
cd aegisscan
python -m aegisscan demo     # verify your setup (no dependencies needed)
```

## Project layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full map. Short version:

- `aegisscan/core/` — models, MITRE mapping, engine, reports
- `aegisscan/scanners/` — one module per scan layer
- `aegisscan/server/` + `aegisscan/web/` — dashboard API and SPA
- `examples/vulnerable-app/` — intentionally vulnerable demo target
- `tests/` — test servers and fixtures

## Adding a scanner module

1. Create `aegisscan/scanners/myscanner.py` with `scan(...) -> list[Finding]`.
2. Register it in `aegisscan/core/engine.py` (`MODULES_FOR_TARGET` and a
   branch in `_run_module`).
3. Add a label in `aegisscan/core/models.py:MODULE_LABELS`.
4. Declare MITRE ATT&CK technique IDs on every finding (`mitre=[...]`) and add
   them to `core/mitre.py` if new.
5. Run the demo + a real scan; the UI and all report formats pick the module
   up automatically.

## Ground rules

- Keep the zero-dependency guarantee (standard library only).
- Every finding needs: description, evidence (redacted), remediation,
  references, severity — and ATT&CK mapping.
- Never commit real secrets; the demo app must only contain fake values.
- Web probes must stay non-destructive.

## Pull requests

1. Fork / branch (`feature/my-change`).
2. Make the change with tests or a reproducible scan that demonstrates it.
3. Run `python -m aegisscan scan --repo . --fail-on critical` on the repo
   itself — it must pass.
4. Open a PR describing what changed and why.
