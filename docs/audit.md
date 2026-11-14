# Audit Events

psina writes security events — sign-ins, failed logins, account creation and
linking, logouts, refused refreshes (token reuse among them), PAT creation and
revocation — as structured log records, one record per event. They answer "who
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
| `user_id`    | success; some failures | The account. On a failure only once the request found or created it: see `login`, refused links in `oauth.sign_in`, `refresh`, the PAT events, and `internal_error` after the account was found |
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
is written for it. A failed `register` with `user_id` (`internal_error`) created
the account but issued no session.

### `login`

Password sign-in (`Login` RPC).

| Field | Values |
| ----- | ------ |
| `reason` | see below |
| `user_id` | On success; on `bad_password` and `no_password` (the targeted account); on `internal_error` once the account was found |

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
| `user_id` | On success; on `link_disabled` and `account_has_password` (the account the link targeted); on `internal_error` once the account was found |
| `reason` | `invalid_request` (provider or redirect URI missing), `oauth_disabled`, `unknown_provider`, `redirect_uri_not_allowed`, `invalid_state` (unknown, expired, replayed or foreign state or browser binding), `exchange_failed` (provider refused the code, or provider outage), `email_missing`, `email_unverified`, `link_disabled` (an account with the email exists, `oauth.autoLinkEmail` is off), `account_has_password` (an account with the email holds a password and is never auto-linked), `internal_error` |

### `oauth.link`

A first OAuth sign-in attached the provider account to an existing account with
the same verified email (`oauth.autoLinkEmail`). Written before the
`oauth.sign_in` record of the same request, also when that sign-in then fails
(`internal_error`): the link stands. Success only: a refused link is an
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
| `user_id` | On success; on `internal_error` once the account was found or created |
| `reason` | `invalid_request` (chain or address missing), `wallet_disabled`, `unsupported_chain`, `invalid_address`, `invalid_challenge` (unknown, expired or replayed nonce, a challenge for another chain or address, or a bad signature), `internal_error` |

### `user.created`

An account was created by an OAuth or wallet sign-in. Written before the
`oauth.sign_in` / `wallet.sign_in` record of the same request, also when that
sign-in then fails (`internal_error`): the account stays. Success only.

Two concurrent first sign-ins with one provider account can both act on the
new account: one writes `user.created`, the other `oauth.link` for the same
`user_id`.

| Field | Values |
| ----- | ------ |
| `method` | `oauth` or `wallet` |
| `provider` | With `method=oauth` |
| `chain` | With `method=wallet` |
| `user_id` | The new account |

### `logout`

Session end (`Logout` RPC). The client is answered success whether or not a
session ended; the record tells the two apart.

| Field | Values |
| ----- | ------ |
| `user_id` | On success (the account whose session ended); on `internal_error` once the token was found |
| `reason` | `invalid_request` (no refresh token in the body or cookie), `unknown_token` (the token names no session; nothing ended), `internal_error` (the session may still be alive; the client gets an error and can retry) |

### `refresh`

A refused `Refresh` RPC. Failures only: a successful refresh is not audited
(see Not Audited).

| Field | Values |
| ----- | ------ |
| `user_id` | On `token_reuse`, `session_ended`, and `internal_error` once the token was found |
| `reason` | see below |

| Reason | Meaning |
| ------ | ------- |
| `invalid_request` | No refresh token in the body or cookie |
| `unknown_token` | The token names no session |
| `token_expired` | The token is past its lifetime |
| `token_reuse` | An already used or revoked token was presented outside the reuse leeway; the whole session was revoked. A stolen token being replayed looks like this |
| `session_ended` | The token was valid and rotated, but the session ended (a logout, or a reuse revocation by a concurrent request) before its successor was saved. Not a replay |
| `unknown_user` | The account behind the token no longer exists |
| `invalid_credentials` | Any other rejection |
| `internal_error` | Server failure |

The client gets the same `invalid refresh token` answer for every rejection.
Duplicate refreshes within `token.refreshReuseLeeway` succeed and are not
audited; they leave an `INFO` diagnostic record
`duplicate refresh within reuse leeway`.

### `pat.create`

Personal access token creation (`CreatePersonalAccessToken` RPC).

| Field | Values |
| ----- | ------ |
| `pat_id` | Success: the new token's id |
| `name` | The token name; on failure as the client sent it (cut to 256 bytes) |
| `expires_at` | Success, when the token expires: RFC 3339, UTC; absent for a token without expiry |
| `user_id` | On success; on failure once the session was authenticated |
| `reason` | `invalid_session` (missing, malformed, expired or unknown session token), `pat_not_allowed` (a PAT was presented: PATs cannot manage PATs), `pat_disabled`, `name_required`, `name_too_long`, `invalid_expiry`, `limit_reached`, `internal_error` |

The token secret and its hash are never logged.

### `pat.revoke`

Personal access token revocation (`RevokePersonalAccessToken` RPC).

| Field | Values |
| ----- | ------ |
| `pat_id` | The token id; on failure as the client sent it (cut to 256 bytes) |
| `name`, `expires_at` | Success: the revoked token's name and expiry, as in `pat.create` |
| `user_id` | On success; on failure once the session was authenticated |
| `reason` | `invalid_session`, `pat_not_allowed`, `pat_disabled`, `not_found` (no token with this id owned by the caller), `internal_error` |

## Not Audited

- `Verify` RPC and `GET /verify`, successful or not: the hot ForwardAuth path,
  one record per proxied request would flood the log. PAT use is tracked in the
  token's `last_used_at` instead.
- Successful `Refresh`: routine, every few minutes per session.
- `ListPersonalAccessTokens`, `GetOAuthURL`, `GetChallenge`: read-only or
  flow starts that change nothing.

## Example

```json
{"time":"2026-01-01T12:00:00Z","level":"WARN","msg":"audit login","audit":true,"event":"login","result":"failure","ip":"203.0.113.7","user_agent":"Mozilla/5.0","user_id":"0190a1b2-...","reason":"bad_password"}
```
