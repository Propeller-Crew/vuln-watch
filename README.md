# vuln-watch

A small security agent for one Ubuntu server. It reads free vulnerability feeds, keeps only
what affects software actually installed on the host, and does one of two things:

- **installs official security updates by itself.** It upgrades only from repos you allow,
  checks that the live sites and services still work, and rolls back automatically if they
  don't;
- **sends you a Telegram message with a short plan** when a human has to act: a reboot, a
  major upgrade, an app's npm/pip dependencies, or no official fix yet.

It does not message when everything is fine, apart from a weekly digest.

## Why the health check matters

`nginx -t` passing does not mean the sites are up. A package upgrade can silently replace
`nginx.conf` with the stock one (no `include sites-enabled/*`). The config stays valid,
but every site disappears. vuln-watch therefore:

1. takes a **baseline**: the HTTP code of every `server_name`, fetched through
   `--resolve name:443:127.0.0.1`, plus `systemctl --failed`, pm2 processes for the
   configured users, and running docker containers;
2. backs up `/etc/nginx` and the package conffiles, and saves the old `.deb` (from the apt
   cache, `apt-get download`, or `dpkg-repack`);
3. upgrades with `--force-confold`, then **moves aside any file the package changed or added
   in `/etc/nginx`** and restores ours;
4. runs `nginx -t`, restarts nginx if its binary changed, and re-checks everything against
   the baseline (with retries);
5. on any regression it **rolls back**: old `.deb`s, configs, and a restart of the broken
   units/pm2 apps. It notifies you and blocks that version until a newer one appears.

It never reboots on its own. It tells you when a reboot is needed, and it detects
"fix installed, but the running kernel is still old".

## Sources (all free, no API keys)

| Source | Used for |
|---|---|
| Ubuntu USN (`ubuntu.com/security/notices.json`) | distro packages: installed version vs the fixed one |
| Ubuntu CVE tracker (`ubuntu.com/security/cves/<id>.json`) | deterministic status per release (released/needed/not-affected) |
| nginx.org security advisories | upstream nginx version ranges plus the directives actually used in config (http2, quic, mail, stream, …) |
| CISA KEV (with a GitHub mirror as fallback) | actively exploited CVEs, matched against dpkg and docker images |
| OSV.dev | production dependencies from `package-lock.json` and pinned `requirements.txt` (covers GHSA) |

When the rules can't decide (vendor packages, unusual products), the `claude -p` CLI judges
whether the host is affected. It uses your logged-in Claude subscription, needs no API key,
and is capped at 10 calls per run.

## Install

```bash
git clone https://github.com/<you>/vuln-watch && cd vuln-watch
sudo ./install.sh                      # copies to /opt/vuln-watch, installs timers
sudo nano /etc/vuln-watch/config.json  # pm2 users, claude user, allowed origins
printf 'TELEGRAM_BOT_TOKEN=...\nTELEGRAM_CHAT_ID=...\n' | sudo tee /etc/vuln-watch/telegram.env >/dev/null
sudo chmod 600 /etc/vuln-watch/telegram.env
sudo vuln-watch notify-test --expect YourBotName   # verifies the bot via getMe, then sends a test message
```

For `/usr/local/bin`: `sudo ln -s /opt/vuln-watch/bin/vuln-watch /usr/local/bin/`.

Requirements: Ubuntu (tested on 24.04), python3 and python3-apt, curl, `dpkg-repack`
(installed by `install.sh`). The `claude` CLI is optional; without it the deterministic
rules are used.

## Commands

```
vuln-watch scan [--dry-run]       # feeds -> match -> urgent patch / notify
vuln-watch patch [--dry-run] [--only pkg ...]
vuln-watch health [--json]        # current liveness snapshot
vuln-watch assess CVE-XXXX-YYYY   # dry-run one nginx advisory (prints the verdict)
vuln-watch test-rollback <pkg>    # upgrades a harmless pkg, injects a failure, checks the rollback
vuln-watch digest [--dry-run]
vuln-watch notify-test [--expect BOT] [--check-only]
vuln-watch inventory
```

`VULN_WATCH_DRY_RUN=1` prints Telegram messages instead of sending them.
`VULN_WATCH_CONFIG=/path.json` uses a different config (handy for a throw-away `state_dir`).

## Timers

| Timer | When | What |
|---|---|---|
| `vuln-watch-scan` | every 4 h | new advisories; patches immediately if an official fix is available |
| `vuln-watch-patch` | 04:30 daily | all pending allowed security updates |
| `vuln-watch-digest` | Monday 10:00 | weekly summary |
| drop-in on `apt-daily-upgrade` | with unattended-upgrades | health baseline before, alert on regressions after |

## Config (`/etc/vuln-watch/config.json`)

See `config.example.json`. Key parts:

- `auto_patch.origins`: what may be installed without asking. Default: Ubuntu
  `-security`, ESM `-security`, nginx.org with `same_minor_only` (1.30.x → 1.30.y only,
  never a branch change).
- `auto_patch.never`: package globs that are never auto-installed.
- `health.pm2_users`, `health.extra_urls`.
- `claude.user` / `claude.bin`: the user whose Claude login is used.
- `inventory.lockfile_roots`: where app lockfiles are searched (dev deps are ignored).

Nothing host-specific lives in the repo. Hostnames, users, and secrets stay in `/etc/vuln-watch/`.

## State

- `/var/lib/vuln-watch/`: `seen.json` (dedupe), `events.jsonl` (digest), `blocked.json`
  (versions that broke something and were rolled back), OSV cache.
- `/var/backups/vuln-watch/<timestamp>/`: `etc.tgz`, old `.deb`s, `apt.log`, `drift/`
  (files a package tried to change). Nothing is deleted, only moved aside.

## License

MIT
