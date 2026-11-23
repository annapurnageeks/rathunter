# Changelog

## 0.1.0 (2026-11-23)

First release, for macOS.

- 14 checks across 7 areas: startup items, login hooks, cron, shell startup files, privacy permissions (TCC), remote access, running processes, network connections, configuration profiles, trusted certificates, proxies, the hosts file, browser extensions and system defenses
- Detects RAT behaviour in scripts: Telegram/Discord control, keylogging, screenshots, webcam, microphone, password theft, download-and-run, self-installing persistence
- Catches items disguised as Apple and fake system processes
- Terminal output, a visual HTML report, and JSON; exit codes for scripting
- Read-only, no network requests, home paths shown as `~`
- Works as a Claude Code skill
