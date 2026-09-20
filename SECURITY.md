# Security policy

## Project status

Abyssal Browser is an experimental, pre-1.0 personal project. It has **not**
been through a third-party security audit, and it should not be relied on to
protect sensitive activity or to provide strong anonymity. It is not Tor.

For an honest account of what has and has not been reviewed, see the "Security
status" section of [`README.md`](README.md) and the self-review in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## Supported versions

Only the latest commit on the default branch and the most recent tagged
pre-release receive security fixes. There are no long-term support branches.

| Version | Supported |
| --- | --- |
| `main` (latest) | Yes |
| Latest tagged pre-release | Yes |
| Anything older | No |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security
vulnerability.**

Use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Fill in the details below.

The direct link is
<https://github.com/AbyssalOath/abyssal-browser/security/advisories/new>.

That channel is private between you and the maintainer, and it does not require
sharing an email address up front. If the button is not available, the
repository has not enabled it yet. In that case, open a minimal public issue
that says only "I would like to report a security issue privately" with no
technical details, and the maintainer will arrange a private channel.

### What to include

- What you found and where (file, crate, or function if you know it).
- Why it is a security issue and not only a bug: what an attacker could
  actually do with it, and under what conditions.
- Steps to reproduce, a proof of concept, or a crashing input if you have one.
- The platform, OS version, kernel version (for sandbox issues), and the commit
  or tag you tested.
- Whether you would like credit, and under what name, or to stay anonymous.

## What to expect

This is a personal project maintained on a best-effort basis, not a funded
product, so these are goals rather than guarantees:

- An acknowledgement within about 7 days.
- An initial assessment, and questions if something is unclear, within about 14
  days.
- A fix or a documented mitigation within about 90 days for confirmed issues,
  sooner for severe ones.
- Coordinated disclosure: please give the maintainer a reasonable chance to fix
  an issue before publishing details. Credit is given in the release notes and
  advisory unless you ask otherwise.

There is **no bug bounty**.

## Scope

**In scope:** anything in this repository.

- The rendering engine (`html`, `css`, `layout`, `render`, `text`).
- JavaScript integration (`renderer/src/script.rs`).
- Sandboxing (`renderer/src/sandbox.rs`) and process isolation (`RendererPool`).
- The IPC boundary (`ipc`), including malformed or hostile messages in either
  direction.
- Decoders that run on untrusted input (`renderer/src/images.rs`, `media.rs`,
  `pdf.rs`).
- The account, crypto, and sync stack (`account`, `storage`, `sync`,
  `sync-server`).
- The privacy layer (`privacy`, `network`), including blocklist bypasses and
  partitioning or fingerprinting leaks that contradict the documented design.
- Downloads, userscripts, DevTools, and packaging scripts.

**Particularly interesting to the maintainer:**

- Any way for content in the renderer to reach the account recovery code,
  derived keys, or decrypted user data in `app`.
- Any sandbox escape or seccomp/Landlock bypass.
- Any way to make `app` allocate or execute something unexpected through a
  crafted IPC reply.
- Any way for the sync server to learn plaintext, or for one account to read or
  overwrite another's data.

**Out of scope:**

- Known gaps already listed in [`THREAT_MODEL.md`](THREAT_MODEL.md). A report
  that confirms or extends one of them is still welcome and useful context, so
  send it anyway, but please expect it to be treated as a known issue.
- Vulnerabilities in third-party dependencies that are not exploitable through
  this project's use of them. Please report those upstream. If a dependency
  issue does affect Abyssal Browser, tell us so we can bump or pin it.
- Rendering incorrectness or missing web features that have no security impact.
- Attacks that require a malicious userscript the user installed themselves, a
  modified binary, or physical access to an unlocked machine.
- Denial of service against a self-hosted `sync-server` that is exposed without
  the recommended TLS proxy and firewalling. The known hardening gaps there are
  documented.
- Social engineering of the maintainer.

## Good-faith research

If you make a good-faith effort to follow this policy, avoid privacy violations
and data destruction, only test against systems you own or have permission to
test, and give the maintainer time to respond, the maintainer will not pursue
action against you. Please do not test against any sync server you do not
operate.

## For people running the software

- Treat this as experimental software. Do not use it as your only browser.
- Keep a copy of your account recovery code somewhere safe. It cannot be
  recovered, and it is stored in plaintext (owner-only file permissions, but
  plaintext) in `account.txt` in your data directory, so protect that
  directory (see [`THREAT_MODEL.md`](THREAT_MODEL.md)).
- If you run `sync-server`, put it behind a TLS-terminating reverse proxy and a
  firewall. It speaks plain HTTP and listens on all interfaces by default.
- The renderer sandbox is real on all three platforms, but only Linux's
  (Landlock and seccomp-bpf) has ever actually run - there is no Mac or
  Windows machine in this project's own development loop. macOS (Seatbelt)
  and Windows (a Job Object plus process mitigation policies) were written
  and cross-type-checked against the real platform APIs, not traced and
  tested, and neither is as thorough as Linux's yet either. See
  [`THREAT_MODEL.md`](THREAT_MODEL.md) for exactly what each does and does
  not cover.
- Build from a tagged source tree yourself if you can. Release binaries are not
  signed.
