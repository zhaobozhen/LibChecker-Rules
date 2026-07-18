# Chart rules

This directory contains declarative statistics shown by LibChecker's chart
page. Source files are reviewed in `rules/` and `icons/`; generated download
artifacts are committed under `cloud/`.

## Layout

- `schema/v1/`: JSON schemas for rules and the generated manifest.
- `rules/`: one reviewed statistic definition per JSON file.
- `icons/`: SVG icons referenced by external rules.
- `tools/build_bundle.py`: deterministic bundle and manifest generator.
- `cloud/v1/`: generated files consumed by LibChecker.

Run the checks from the repository root:

```shell
python3 -m unittest chart.tools.test_build_bundle
python3 chart/tools/build_bundle.py --bundle-version 10
```

The APK never executes code from this repository. Rules only compose bounded,
declarative evidence primitives implemented by the installed LibChecker
version.

Schema v1 supports numeric comparisons on `target_sdk`, exact library-name
membership through `native_library`, recursive `all`/`any`/`not` conditions,
DEX class queries, and manifest receiver actions. A DEX class query may combine
a class-name pattern, string constants, and method references; constraints in
one query must be satisfied by the same class.
