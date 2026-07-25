# ShieldKit Explainer

Public-facing system explainer for ShieldKit: system map, covenants & state tip,
action flows, settlement anatomy, live-set lab, fees, capacity, and operator paths.

## Serve locally

```bash
# from repo root
python3 -m http.server 8765 --directory explainer

# or
npx --yes serve explainer -l 8765
```

Open **http://127.0.0.1:8765/**

## GitHub Pages (optional)

Point Pages at `/explainer` on `main`, or copy this folder into `docs/` and
enable Pages from `/docs`.

## Stack

Static HTML + CSS + ES modules. No build step. No tracking.
