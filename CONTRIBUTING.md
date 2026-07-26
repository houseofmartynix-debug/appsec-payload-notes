# Contributing Guidelines

Thanks for your interest in improving **AppSec Payload Notes**!

## Scope

This repository is for:

- Defensive security research
- Authorized penetration testing
- CTF challenges and security education
- Bug bounty methodology

Contributions that are clearly intended for **unauthorized use**, **malware development**, **mass exploitation**, or **detection evasion for criminal purposes** will be rejected.

## How to Contribute

1. **Fork** the repository.
2. **Create a branch** from `main` named `feat/<short-description>` or `fix/<short-description>`.
3. **Add or edit** payloads in the appropriate folder.
4. Open a **Pull Request** with:
   - A clear title
   - A short description of what changed and why
   - Reference to any source (CVE, blog post, advisory)

## Style Guide

- Keep payloads **concise** and grouped by **technique**.
- Prefix new sections with `##` headers in the folder's `README.md`.
- For long payload lists, wrap them in fenced code blocks with the correct language tag.
- Cite the source whenever a payload is taken from a public writeup, CVE, or research paper.
- Don't include sensitive data, real exploits against unpatched systems, or credentials.

## File Layout

```
Category Name/
  README.md          # main documentation
  Files/             # optional: PoC files, exploit scripts
  Intruder/          # optional: wordlists
  Images/            # optional: screenshots / diagrams
```

## Reporting Issues

If you find inaccurate content, broken links, or unsafe examples, open an issue and tag it `bug`, `docs`, or `safety`.

## Code of Conduct

Be respectful, constructive, and on-topic. Do not solicit attacks against specific real-world targets.

---

Maintained by **Marco Selva**.
