# Drift_Integration

Internal helper service for our Salesforce ↔ Drift sync. Owned by RevOps Platform.

## Configuration

Service config lives in `config/`. The runtime reads `secrets.yaml` for the OAuth refresh token used to mint short-lived access tokens against Salesforce.

`app.example.yaml` is the public template for new environments. Copy it to `app.yaml` locally before bringing up a new replica.

## Layout

```
config/
  secrets.yaml         # production refresh token + AWS keys (do not commit secrets here)
  app.example.yaml     # public template
```

## Notes

> This repository is a synthetic target for a detection-engineering lab.
> All values in `config/secrets.yaml` are clearly-marked synthetic. The repo is intended to be scanned by TruffleHog as part of an emulation of T1552.001.
> See `../../README.md` (Emulation 1) in the parent project for context.
