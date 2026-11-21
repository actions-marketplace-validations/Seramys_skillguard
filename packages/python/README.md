# seramys-skillguard (Python)

Python entry point for [SkillGuard](https://github.com/Seramys/skillguard).

> 0.3.0 publishes per-platform wheels: win_amd64, manylinux_2_17_x86_64, and macOS arm64/universal2.

```bash
pip install seramys-skillguard
skillguard scan ./skills --fail-on high
```

The package runs the native `skillguard` binary. Resolution order:

1. `SKILLGUARD_BINARY`
2. bundled `skillguard/_bin/skillguard[.exe]`
3. repository `target/release` or `dist/` (development only)
4. `skillguard` on `PATH`

To create a wheel with the binary bundled:

```bash
scripts/package-python.sh
# or
python -m pip install build
python -m build
```