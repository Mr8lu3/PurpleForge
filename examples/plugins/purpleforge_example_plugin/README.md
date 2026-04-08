# purpleforge-example-plugin

Demonstrates the PurpleForge step handler plugin system. Adds one new step
type: `http_head_baseline`.

**Authorized targets only. Defensive assessment only.**

## Installation

From the example plugin directory:

```
pip install -e examples/plugins/purpleforge_example_plugin
```

## What it adds

| Step type | Description |
|---|---|
| `http_head_baseline` | Issues an HTTP HEAD request and records response headers (server, content-type). No body fetched, no payload injected. |

## Usage in a scenario YAML

```yaml
steps:
  - id: head_check
    type: http_head_baseline
    description: "Fingerprint server headers via HEAD"
    parameters:
      path: /
```

## How it works

`handlers.py` imports `register` from `purpleforge.runners.plugins` and
decorates `handle_http_head_baseline` with `@register("http_head_baseline")`.
When PurpleForge loads entry points (via `registry.load_entry_points()`), it
imports this module, the decorator fires, and the handler is available to any
WebRunner instance.
