//! `sync-server` — the real, persistent server `HttpSyncClient` talks
//! to (see `app`'s `SYNC_SERVER_URL`). Three things graduate this from
//! a demo to something safe to leave running:
//!   1. Storage is `sync::FileSyncServer`, not `FakeSyncServer` — each
//!      account's blob lives in its own file under `data_dir` (default
//!      `sync-server-data/`, override with `ABYSSAL_SYNC_DATA_DIR`), so
//!      restarting this process no longer loses every account's data.
//!   2. `rate_limit::RateLimiter` caps requests per source IP and locks
//!      out an account_id after repeated failed-auth attempts — see
//!      that module's docs for exactly what it does and doesn't defend
//!      against.
//!   3. `FileSyncServer` keeps rotating local backups of every version
//!      it overwrites (default 10 per account, override with
//!      `ABYSSAL_SYNC_BACKUP_RETENTION`) — see that recovery from a bad
//!      push ("client-side merge bug clobbered my bookmarks") without
//!      needing full multi-node replication, which is overkill for a
//!      single-operator, single-instance deployment. Run this binary
//!      with `--restore <account_id> <version>` to bring a specific
//!      backed-up version back to being live (see `restore_account`
//!      below); `--list-backups <account_id>` shows what's available.
//!
//! Still NOT done (see `sync`'s and `account`'s own module docs for the
//! rest of the list): TLS termination (run this behind a real reverse
//! proxy/load balancer that terminates TLS — it speaks plain HTTP),
//! and backups above are still local-disk-only — an off-box copy of
//! `data_dir` (e.g. a periodic rsync to another machine) is an
//! operational step outside what this binary can do for you, since it
//! has no access to any "somewhere else" to put one.

mod rate_limit;

use std::sync::Mutex;

use rate_limit::RateLimiter;
use sync::{FileSyncServer, SyncError, SyncTransport};
use tiny_http::{Header, Method, Response, Server};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--restore") => return restore_account(&args[2..]),
        Some("--list-backups") => return list_backups(&args[2..]),
        Some(unknown) if unknown.starts_with('-') => {
            eprintln!("unknown flag {unknown:?} (expected --restore or --list-backups)");
            std::process::exit(1);
        }
        _ => {}
    }

    let data_dir =
        std::env::var("ABYSSAL_SYNC_DATA_DIR").unwrap_or_else(|_| "sync-server-data".to_string());
    let backup_retention = std::env::var("ABYSSAL_SYNC_BACKUP_RETENTION")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10);
    let store = Mutex::new(
        FileSyncServer::open_with_retention(&data_dir, backup_retention)
            .unwrap_or_else(|e| panic!("failed to open sync data directory {data_dir:?}: {e}")),
    );
    let limiter = Mutex::new(RateLimiter::new());

    let server = Server::http("0.0.0.0:7878").expect("failed to bind to 0.0.0.0:7878");
    println!("sync-server listening on http://0.0.0.0:7878 (data: {data_dir})");

    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();
        let remote_ip = request.remote_addr().map(|addr| addr.ip());

        if let Some(ip) = remote_ip {
            let mut limiter = limiter.lock().expect("rate limiter mutex poisoned");
            if let Err(blocked) = limiter.check_ip(ip) {
                let _ = request.respond(too_many_requests(blocked.retry_after));
                continue;
            }
        }

        let account_id = match url.strip_prefix("/accounts/") {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => {
                let _ = request.respond(
                    Response::from_string("expected /accounts/{account_id}").with_status_code(404),
                );
                continue;
            }
        };

        let auth_secret = match extract_auth_secret(&request) {
            Some(secret) => secret,
            None => {
                let _ = request.respond(
                    Response::from_string(
                        "missing or malformed Authorization: Bearer <64-hex-char secret>",
                    )
                    .with_status_code(401),
                );
                continue;
            }
        };

        {
            let mut limiter = limiter.lock().expect("rate limiter mutex poisoned");
            if let Err(blocked) = limiter.check_account_lockout(&account_id) {
                let _ = request.respond(too_many_requests(blocked.retry_after));
                continue;
            }
        }

        let mut store = store.lock().expect("store mutex poisoned");

        match method {
            Method::Put => {
                let expected_version = request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("X-Expected-Version"))
                    .and_then(|h| h.value.as_str().parse::<u64>().ok())
                    .unwrap_or(0);

                let mut body = Vec::new();
                if request.as_reader().read_to_end(&mut body).is_err() {
                    let _ = request.respond(
                        Response::from_string("failed to read body").with_status_code(400),
                    );
                    continue;
                }

                match store.push(&account_id, &auth_secret, body, expected_version) {
                    Ok(new_version) => {
                        limiter
                            .lock()
                            .expect("rate limiter mutex poisoned")
                            .record_auth_success(&account_id);
                        let _ = request.respond(
                            Response::from_string(new_version.to_string()).with_status_code(200),
                        );
                    }
                    Err(SyncError::Unauthorized(_)) => {
                        limiter
                            .lock()
                            .expect("rate limiter mutex poisoned")
                            .record_auth_failure(&account_id);
                        let _ = request
                            .respond(Response::from_string("unauthorized").with_status_code(401));
                    }
                    Err(SyncError::Conflict { server_version }) => {
                        let _ = request.respond(
                            Response::from_string(server_version.to_string()).with_status_code(409),
                        );
                    }
                    Err(SyncError::AccountNotFound(_)) => {
                        unreachable!("push never returns AccountNotFound")
                    }
                    Err(SyncError::Transport(msg)) => {
                        eprintln!("storage error on push for {account_id}: {msg}");
                        let _ = request.respond(
                            Response::from_string("internal storage error").with_status_code(500),
                        );
                    }
                }
            }
            Method::Get => match store.pull(&account_id, &auth_secret) {
                Ok(blob) => {
                    limiter
                        .lock()
                        .expect("rate limiter mutex poisoned")
                        .record_auth_success(&account_id);
                    let version_header = Header::from_bytes(
                        &b"X-Version"[..],
                        blob.version.to_string().into_bytes(),
                    )
                    .expect("static header name is valid");
                    let _ = request.respond(
                        Response::from_data(blob.ciphertext)
                            .with_status_code(200)
                            .with_header(version_header),
                    );
                }
                Err(SyncError::AccountNotFound(_)) => {
                    let _ =
                        request.respond(Response::from_string("not found").with_status_code(404));
                }
                Err(SyncError::Unauthorized(_)) => {
                    limiter
                        .lock()
                        .expect("rate limiter mutex poisoned")
                        .record_auth_failure(&account_id);
                    let _ = request
                        .respond(Response::from_string("unauthorized").with_status_code(401));
                }
                Err(SyncError::Conflict { .. }) => unreachable!("pull never returns Conflict"),
                Err(SyncError::Transport(msg)) => {
                    eprintln!("storage error on pull for {account_id}: {msg}");
                    let _ = request.respond(
                        Response::from_string("internal storage error").with_status_code(500),
                    );
                }
            },
            _ => {
                let _ = request.respond(
                    Response::from_string("only GET/PUT are supported").with_status_code(405),
                );
            }
        }
    }
}

fn too_many_requests(retry_after: std::time::Duration) -> Response<std::io::Cursor<Vec<u8>>> {
    let retry_after_secs = retry_after.as_secs().max(1).to_string();
    let header = Header::from_bytes(&b"Retry-After"[..], retry_after_secs.into_bytes())
        .expect("static header name and numeric value are valid");
    Response::from_string("too many requests — try again later")
        .with_status_code(429)
        .with_header(header)
}

fn extract_auth_secret(request: &tiny_http::Request) -> Option<[u8; 32]> {
    let header = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))?;
    let hex = header.value.as_str().strip_prefix("Bearer ")?;
    if hex.len() != 64 {
        return None;
    }
    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(secret)
}

/// Opens the same `data_dir` the server itself would (respecting
/// `ABYSSAL_SYNC_DATA_DIR`), for the CLI-only `--restore`/
/// `--list-backups` operator commands. Retention doesn't matter for
/// these — they only ever read or overwrite-with-a-known-good-copy,
/// never prune — so the default is fine regardless of what the
/// running server was configured with.
fn open_store_for_cli() -> FileSyncServer {
    let data_dir =
        std::env::var("ABYSSAL_SYNC_DATA_DIR").unwrap_or_else(|_| "sync-server-data".to_string());
    FileSyncServer::open(&data_dir)
        .unwrap_or_else(|e| panic!("failed to open sync data directory {data_dir:?}: {e}"))
}

/// `sync-server --restore <account_id> <version>` — brings a specific
/// backed-up version back to being that account's live blob. An
/// operator-only recovery path (see module docs): there is no HTTP
/// route for this, deliberately, since a client has no legitimate
/// reason to roll back another version's data out from under a
/// concurrent device.
fn restore_account(args: &[String]) {
    let [account_id, version] = args else {
        eprintln!("usage: sync-server --restore <account_id> <version>");
        std::process::exit(1);
    };
    let version: u64 = version.parse().unwrap_or_else(|_| {
        eprintln!("version must be a non-negative integer, got {version:?}");
        std::process::exit(1);
    });

    match open_store_for_cli().restore_backup(account_id, version) {
        Ok(()) => println!("restored account {account_id} to version {version}"),
        Err(e) => {
            eprintln!("failed to restore account {account_id} to version {version}: {e}");
            std::process::exit(1);
        }
    }
}

/// `sync-server --list-backups <account_id>` — shows which versions
/// are currently available to `--restore`, oldest first.
fn list_backups(args: &[String]) {
    let [account_id] = args else {
        eprintln!("usage: sync-server --list-backups <account_id>");
        std::process::exit(1);
    };

    match open_store_for_cli().list_backup_versions(account_id) {
        Ok(versions) if versions.is_empty() => {
            println!("no backups found for account {account_id}")
        }
        Ok(versions) => {
            println!("backed-up versions for account {account_id} (oldest first):");
            for v in versions {
                println!("  {v}");
            }
        }
        Err(e) => {
            eprintln!("failed to list backups for account {account_id}: {e}");
            std::process::exit(1);
        }
    }
}
