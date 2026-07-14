# Publish AdversaryFlow to GitHub

## Git command line

Create an empty repository named `adversaryflow`, then run from this directory:

```bash
git init
git branch -M main
git add .
git commit -m "Initial AdversaryFlow v0.2.1 release"
git remote add origin https://github.com/YOUR-ACCOUNT/adversaryflow.git
git push -u origin main
```

Replace `YOUR-ACCOUNT` with the GitHub user or organization that owns the new repository.

## GitHub web upload

Create an empty repository without an auto-generated README, license, or `.gitignore`. Extract the release ZIP, open the extracted project directory, and upload its contents so `README.md`, `pyproject.toml`, `src/`, and `.github/` are at the repository root.

## Recommended repository settings

Enable GitHub Actions, private vulnerability reporting, Dependabot alerts, secret scanning where available, and branch protection requiring the `test` workflow before merging to `main`.
