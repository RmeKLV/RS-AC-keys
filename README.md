# RS-AC-keys

Public key list for the RS-AC anti-cheat plugin. Servers download `list.txt` at every map change.

- `keys.txt` - edited by wsad's `keygen.py` (cancels, paid-until dates, server moves). Only key IDs, server codes
  and dates: no key texts, no names, no payments.
- `list.txt` - `keys.txt` signed every day by the GitHub Action (`.github/workflows/sign.yml`, secret `LIST_KEY`).
  Servers refuse a list older than 7 days, a lower list number, or a bad signature.
- `cert.txt` - wsad's master signature over the list key.

Mirrors the plugin uses: raw.githubusercontent.com, cdn.jsdelivr.net, and GitHub Pages of this repo.
