package auth

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/foxcool/psina/provider/oauth"
)

// Audit events are security events (sign-ins, account changes) written as one
// slog record each, for operators to answer "who signed in to account X, when
// and from where". They are emitted by the Handler, not the Service: only the
// Handler sees the client IP and user agent, and an event without them cannot
// answer "from where". The record shape is a public contract listed in
// docs/audit.md; never put a credential, token, hash or the identifier a user
// typed into one.
//
// Every record carries:
//
//	audit=true   marker to route audit records apart from diagnostics
//	event        stable event name (auditEvent* below)
//	result       "success" or "failure"
//	reason       failure cause (audit reason constants), failures only
//	ip           client IP (see Handler.clientIP)
//	user_agent   client User-Agent, truncated
//	user_id      the account, when known
const (
	auditEventRegister     = "register"
	auditEventLogin        = "login"
	auditEventOAuthSignIn  = "oauth.sign_in"
	auditEventOAuthLink    = "oauth.link"
	auditEventWalletSignIn = "wallet.sign_in"
	auditEventUserCreated  = "user.created"
)

// auditMethod is how a user.created account signed in.
type auditMethod string

const (
	auditMethodOAuth  auditMethod = "oauth"
	auditMethodWallet auditMethod = "wallet"
)

const (
	auditResultSuccess = "success"
	auditResultFailure = "failure"
)

// Login failure reasons. A Provider reports them through CredentialsError.
const (
	ReasonUnknownUser = "unknown_user"
	ReasonBadPassword = "bad_password"
	// ReasonNoPassword is an existing account without a password (created by
	// OAuth or wallet sign-in).
	ReasonNoPassword = "no_password"
	// ReasonMalformedCredentials is an identifier that is not an email or an
	// empty password: nothing was looked up.
	ReasonMalformedCredentials = "malformed_credentials" // #nosec G101 -- a reason name, not a credential
	// ReasonInvalidCredentials is a rejection from a Provider that does not
	// say why.
	ReasonInvalidCredentials = "invalid_credentials" // #nosec G101 -- a reason name, not a credential
)

// Reasons shared by every event family.
const (
	reasonInvalidRequest = "invalid_request"
	reasonInternalError  = "internal_error"
)

// maxAuditValue caps a client-controlled value (User-Agent, provider or chain
// name) so one request cannot write an arbitrarily large audit record.
const maxAuditValue = 256

// clientAttr is an attribute whose value the client chose, truncated.
func clientAttr(key, value string) slog.Attr {
	if len(value) > maxAuditValue {
		value = value[:maxAuditValue]
	}
	return slog.String(key, value)
}

// CredentialsError is a rejected sign-in that tells the audit log why. It
// matches ErrInvalidCredentials and has its text, so callers and clients still
// cannot tell an unknown account from a wrong password, and the identifier
// typed into a failed login never reaches a log through it.
type CredentialsError struct {
	Reason string // Reason* constant
	UserID string // the account, when one was found
}

func (e *CredentialsError) Error() string {
	return ErrInvalidCredentials.Error()
}

// Is matches ErrInvalidCredentials like every other credential rejection.
func (e *CredentialsError) Is(target error) bool {
	return target == ErrInvalidCredentials
}

// accountChange is the account a sign-in acted on and what it did to it.
type accountChange struct {
	userID  string
	created bool
	linked  bool // auto-linked a provider account to an existing user
}

// accountError is a failure after the service found or created the account.
// The audit record names the account, and a creation or link committed before
// the failure is recorded: it stands even though the request failed.
type accountError struct {
	accountChange
	err error
}

func (e *accountError) Error() string { return e.err.Error() }
func (e *accountError) Unwrap() error { return e.err }

// failedAccount returns the account behind a failed request, if it was known.
func failedAccount(err error) *accountError {
	var ae *accountError
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}

// accountAttrs names the account behind a failed request, if it was known.
func accountAttrs(err error) []slog.Attr {
	if ae := failedAccount(err); ae != nil {
		return []slog.Attr{slog.String("user_id", ae.userID)}
	}
	return nil
}

// WithAuditLogger routes audit events to logger. Default: slog.Default(), whose
// level may drop them; give audit its own handler to keep them regardless of
// the diagnostic log level.
func WithAuditLogger(logger *slog.Logger) HandlerOption {
	return func(h *Handler) {
		h.audit = logger
	}
}

// auditLogger returns the configured audit logger, resolved per call so a
// later slog.SetDefault is honoured.
func (h *Handler) auditLogger() *slog.Logger {
	if h.audit != nil {
		return h.audit
	}
	return slog.Default()
}

// auditSuccess writes a successful event at info level.
func (h *Handler) auditSuccess(ctx context.Context, req connect.AnyRequest, event, userID string, attrs ...slog.Attr) {
	attrs = append(attrs, slog.String("user_id", userID))
	h.writeAudit(ctx, req, slog.LevelInfo, event, auditResultSuccess, attrs)
}

// auditFailure writes a failed event at warn level.
func (h *Handler) auditFailure(ctx context.Context, req connect.AnyRequest, event, reason string, attrs ...slog.Attr) {
	attrs = append(attrs, slog.String("reason", reason))
	h.writeAudit(ctx, req, slog.LevelWarn, event, auditResultFailure, attrs)
}

// auditSignIn writes a successful sign-in, preceded by the account change it
// made, if any.
func (h *Handler) auditSignIn(ctx context.Context, req connect.AnyRequest, event string, method auditMethod, change accountChange, attr slog.Attr) {
	h.auditAccountChange(ctx, req, method, change, attr)
	h.auditSuccess(ctx, req, event, change.userID, attr, slog.Bool("new_user", change.created))
}

// auditSignInFailure writes a failed sign-in, preceded by an account change
// the service committed before the failure.
func (h *Handler) auditSignInFailure(ctx context.Context, req connect.AnyRequest, event string, method auditMethod, reason string, err error, attr slog.Attr) {
	attrs := []slog.Attr{attr}
	if ae := failedAccount(err); ae != nil {
		h.auditAccountChange(ctx, req, method, ae.accountChange, attr)
		attrs = append(attrs, slog.String("user_id", ae.userID))
	}
	h.auditFailure(ctx, req, event, reason, attrs...)
}

func (h *Handler) auditAccountChange(ctx context.Context, req connect.AnyRequest, method auditMethod, change accountChange, attr slog.Attr) {
	switch {
	case change.created:
		h.auditSuccess(ctx, req, auditEventUserCreated, change.userID, slog.String("method", string(method)), attr)
	case change.linked:
		h.auditSuccess(ctx, req, auditEventOAuthLink, change.userID, attr)
	}
}

func (h *Handler) writeAudit(ctx context.Context, req connect.AnyRequest, level slog.Level, event, result string, attrs []slog.Attr) {
	all := make([]slog.Attr, 0, 5+len(attrs))
	all = append(all,
		slog.Bool("audit", true),
		slog.String("event", event),
		slog.String("result", result),
		slog.String("ip", h.clientIP(req.Peer().Addr, req.Header())),
		clientAttr("user_agent", req.Header().Get("User-Agent")),
	)
	h.auditLogger().LogAttrs(ctx, level, "audit "+event, append(all, attrs...)...)
}

// registerFailureReason maps a Service.Register error to its audit reason.
func registerFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrUserExists):
		return "user_exists"
	case errors.Is(err, ErrInvalidEmail):
		return "invalid_email"
	case errors.Is(err, ErrPasswordTooShort):
		return "password_too_short"
	case errors.Is(err, ErrPasswordTooLong):
		return "password_too_long"
	default:
		return reasonInternalError
	}
}

// loginFailure maps a Service.Login error to its audit reason and, when the
// account was found, its user_id attribute.
func loginFailure(err error) (string, []slog.Attr) {
	var cerr *CredentialsError
	switch {
	case errors.As(err, &cerr):
		reason := cerr.Reason
		if reason == "" {
			reason = ReasonInvalidCredentials
		}
		if cerr.UserID != "" {
			return reason, []slog.Attr{slog.String("user_id", cerr.UserID)}
		}
		return reason, nil
	case errors.Is(err, ErrInvalidCredentials):
		return ReasonInvalidCredentials, nil
	default:
		return reasonInternalError, accountAttrs(err)
	}
}

// oauthFailureReason maps a Service.OAuthCallback error to its audit reason.
func oauthFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrOAuthDisabled):
		return "oauth_disabled"
	case errors.Is(err, ErrOAuthProviderUnknown):
		return "unknown_provider"
	case errors.Is(err, oauth.ErrRedirectURINotAllowed):
		return "redirect_uri_not_allowed"
	case errors.Is(err, ErrOAuthStateInvalid):
		return "invalid_state"
	case errors.Is(err, ErrOAuthExchangeFailed):
		return "exchange_failed"
	case errors.Is(err, ErrOAuthEmailRequired):
		return "email_missing"
	case errors.Is(err, ErrOAuthEmailUnverified):
		return "email_unverified"
	case errors.Is(err, ErrOAuthLinkDisabled):
		return "link_disabled"
	case errors.Is(err, ErrOAuthAccountHasPassword):
		return "account_has_password"
	default:
		return reasonInternalError
	}
}

// walletFailureReason maps a Service.AuthenticateWallet error to its audit reason.
func walletFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrWalletDisabled):
		return "wallet_disabled"
	case errors.Is(err, ErrWalletChainUnsupported):
		return "unsupported_chain"
	case errors.Is(err, ErrWalletAddressInvalid):
		return "invalid_address"
	case errors.Is(err, ErrWalletChallengeInvalid):
		return "invalid_challenge"
	default:
		return reasonInternalError
	}
}
