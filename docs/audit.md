# Audit Events

psina writes security events — sign-ins, failed logins, account creation and
linking — as structured log records, one record per event. They answer "who
signed in to account X, when and from where" during an incident. There is no
audit table: records go to stdout next to the diagnostic log, and a log
collector keeps them.

This catalog is a public contract. Event names, field names and reason values
change only with a release note.

## Routing

Every audit record carries `audit=true`. Route on it to keep audit records
apart from diagnostic ones (e.g. a separate index with a longer retention).

**Standalone server.** Audit records use the configured `logger.format` (JSON
or text) on stdout, but have their own level: `logger.level` (`warn`, `error`)
never drops them. Successes are written at `INFO`, failures at `WARN`.

**Library.** Pass `auth.WithAuditLogger(logger)` to `auth.NewHandler`. Without
it records go to `slog.Default()`, whose level may drop the `INFO` successes;
give audit a logger of its own to keep them. Events are written by the
`Handler`: an app calling `Service` methods directly gets none, because only the
handler sees the client address.

## Common Fields

| Field        | Present        | Meaning |
| ------------ | -------------- | ------- |
| `msg`        | always         | `audit <event>` |
| `audit`      | always         | `true` — the marker |
| `event`      | always         | Event name, see below |
| `result`     | always         | `success` or `failure` |
| `ip`         | always         | Client IP. Behind a gateway it is correct only with `server.trustedProxies` set (see [architecture §4.5](architecture.md#45-client-ip-behind-a-gateway)); `unknown` if the peer address does not parse |
| `user_agent` | always         | Client `User-Agent`, cut to 256 bytes; empty if not sent |
| `user_id`    | success; some failures | The account. On failures only where the account is known (see `login`) |
| `reason`     | failure        | Why it failed, see each event |

Never in any record: passwords, password hashes, access or refresh tokens, PAT
secrets, OAuth codes, state or binding values, wallet signatures or nonces, and
the email or identifier a user typed into a failed login (a password typed into
the email field must not reach the log). Emails and wallet addresses are not
logged at all; `user_id` names the account.

`internal_error` as a reason means a storage or other server failure; the
diagnostic log has an `ERROR` record with the cause.

## Events

### `register`

Password registration (`Register` RPC).

| Field | Values |
| ----- | ------ |
| `reason` | `user_exists`, `invalid_email`, `password_too_short`, `password_too_long`, `internal_error` |

A successful `register` is also the creation of the account; no `user.created`
is written for it.

### `login`

Password sign-in (`Login` RPC).

| Field | Values |
| ----- | ------ |
| `reason` | see below |
| `user_id` | on success; on `bad_password` and `no_password` (the targeted account) |

| Reason | Meaning |
| ------ | ------- |
| `unknown_user` | No account with this email |
| `bad_password` | Account exists, wrong password |
| `no_password` | Account exists without a password (created by OAuth or wallet sign-in) |
| `malformed_credentials` | The identifier is not an email, or the password is empty; nothing was looked up |
| `invalid_credentials` | A custom `auth.Provider` refused without a reason (see below) |
| `internal_error` | Server failure |

The client gets the same `invalid credentials` answer for every reason.

A custom `auth.Provider` reports the reason by returning an
`*auth.CredentialsError` (it matches `auth.ErrInvalidCredentials`); a bare
`auth.ErrInvalidCredentials` is logged as `invalid_credentials`.

### `oauth.sign_in`

OAuth sign-in completion (`OAuthCallback` RPC). `GetOAuthURL` writes nothing.

| Field | Values |
| ----- | ------ |
| `provider` | Provider name as the client sent it (`google`, `github`; cut to 256 bytes) |
| `new_user` | Success only: `true` if this sign-in created the account |
| `reason` | `invalid_request` (provider or redirect URI missing), `oauth_disabled`, `unknown_provider`, `redirect_uri_not_allowed`, `invalid_state` (unknown, expired, replayed or foreign state or browser binding), `exchange_failed` (provider refused the code, or provider outage), `email_missing`, `email_unverified`, `link_disabled` (an account with the email exists, `oauth.autoLinkEmail` is off), `account_has_password` (an account with the email holds a password and is never auto-linked), `internal_error` |

### `oauth.link`

A first OAuth sign-in attached the provider account to an existing account with
the same verified email (`oauth.autoLinkEmail`). Written before the
`oauth.sign_in` success of the same request. Success only: a refused link is an
`oauth.sign_in` failure (`link_disabled`, `account_has_password`).

| Field | Values |
| ----- | ------ |
| `provider` | The provider now linked |
| `user_id` | The existing account |

An unexpected `oauth.link` for an account is the trace of a takeover through a
provider account with the victim's email.

### `wallet.sign_in`

Wallet sign-in completion (`AuthenticateWallet` RPC). `GetChallenge` writes
nothing.

| Field | Values |
| ----- | ------ |
| `chain` | Chain name as the client sent it (cut to 256 bytes) |
| `new_user` | Success only: `true` if this sign-in created the account |
| `reason` | `invalid_request` (chain or address missing), `wallet_disabled`, `unsupported_chain`, `invalid_address`, `invalid_challenge` (unknown, expired or replayed nonce, a challenge for another chain or address, or a bad signature), `internal_error` |

### `user.created`

An account was created by an OAuth or wallet sign-in. Written before the
`oauth.sign_in` / `wallet.sign_in` success of the same request. Success only.

| Field | Values |
| ----- | ------ |
| `method` | `oauth` or `wallet` |
| `provider` | With `method=oauth` |
| `chain` | With `method=wallet` |
| `user_id` | The new account |

## Not Audited

- `Verify` RPC and `GET /verify`, successful or not: the hot ForwardAuth path,
  one record per proxied request would flood the log.
- Successful `Refresh`: routine, every few minutes per session.
- Logout, refresh reuse and refusal, PAT create and revoke: planned. Refresh
  reuse is today a diagnostic `WARN` record `token reuse detected` with
  `user_id`, `ip` and `user_agent`, without the `audit` marker.

## Example

```json
{"time":"2026-01-01T12:00:00Z","level":"WARN","msg":"audit login","audit":true,"event":"login","result":"failure","ip":"203.0.113.7","user_agent":"Mozilla/5.0","user_id":"0190a1b2-...","reason":"bad_password"}
```
