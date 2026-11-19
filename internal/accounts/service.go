// Package accounts implements the customer-account domain: sign-up (with
// ALTCHA bot protection and email verification), Argon2id password
// sessions (httpOnly signed cookies — there is no session table, so the
// cookie signature is bound to the user's credential fingerprint), TOTP
// (optional for members, required for owners) and org membership roles.
//
// Schema note: there is no sessions table — sessions are stateless
// signed cookies bound to the credential fingerprint (credential change
// or disable kills them). Verification state lives on
// users.email_verified_at; the auth.email_verified audit row records
// the event.
package accounts

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/mailer"
)

// Org membership roles (memberships_role_check).
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
	RoleViewer = "viewer"
)

// Subscription plan/status values used at sign-up (subscriptions checks).
const (
	planTrial     = "trial"
	statusTrial   = "trialing"
	licenceKeyPfx = "SPTL-" // trial licence keys
)

// TOTPIssuer labels the otpauth provisioning URI.
const TOTPIssuer = "ServerPerch"

// Domain errors surfaced as API responses.
var (
	ErrEmailTaken        = errors.New("email already registered")
	ErrBadCredentials    = errors.New("invalid email or password")
	ErrCaptchaFailed     = errors.New("captcha verification failed")
	ErrBadToken          = errors.New("invalid or expired token")
	ErrBadTOTP           = errors.New("invalid TOTP code")
	ErrTOTPMissing       = errors.New("no pending TOTP enrolment")
	ErrTOTPRequiredOwner = errors.New("organisation owners must keep TOTP enabled")
	ErrTOTPRequiredStaff = errors.New("staff accounts must keep TOTP enabled")
	ErrAlreadyMember     = errors.New("user is already a member of this organisation")
	ErrLastOwner         = errors.New("cannot remove or demote the last organisation owner")
	ErrValidation        = errors.New("validation failed")
	ErrForbidden         = errors.New("insufficient role")
	ErrNotFound          = errors.New("not found")
)

const (
	minPasswordLen = 8
	maxPasswordLen = 256
	// verifyTokenTTL bounds email-verification links.
	verifyTokenTTL = 24 * time.Hour
)

// Options configures a Service.
type Options struct {
	// Secret keys session cookies, verification tokens and TOTP sealing.
	// Must be non-empty (generate a random one when unconfigured).
	Secret        []byte
	SessionTTL    time.Duration
	SecureCookies bool
	PublicBaseURL string
	// AltchaSecret enables sign-up bot protection when non-empty.
	AltchaSecret    []byte
	AltchaMaxNumber int
	// Trial subscription granted at sign-up.
	TrialDays        int
	TrialMaxMachines int
	// Queue receives mail.send jobs (verification/dunning email). May be
	// nil in tests — outbound mail is then skipped.
	Queue *jobs.Queue
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Service is the accounts domain service.
type Service struct {
	db    *sql.DB
	q     *dbq.Queries
	queue *jobs.Queue

	secret        []byte
	altchaSecret  []byte
	altchaMax     int
	ttl           time.Duration
	secureCookies bool
	publicBase    string
	trialDays     int
	trialMachines int
	now           func() time.Time
}

// New returns the accounts Service over db.
func New(db *sql.DB, opts Options) (*Service, error) {
	if len(opts.Secret) == 0 {
		return nil, errors.New("accounts: auth secret required")
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		db:            db,
		q:             dbq.New(db),
		queue:         opts.Queue,
		secret:        opts.Secret,
		altchaSecret:  opts.AltchaSecret,
		altchaMax:     max(opts.AltchaMaxNumber, 1),
		ttl:           opts.SessionTTL,
		secureCookies: opts.SecureCookies,
		publicBase:    strings.TrimRight(opts.PublicBaseURL, "/"),
		trialDays:     max(opts.TrialDays, 1),
		trialMachines: max(opts.TrialMaxMachines, 1),
		now:           now,
	}, nil
}

// NewMust is New that panics on error — for process wiring where the
// options are known-valid.
func NewMust(db *sql.DB, opts Options) *Service {
	s, err := New(db, opts)
	if err != nil {
		panic(err)
	}
	return s
}

// CaptchaEnabled reports whether sign-up bot protection is on.
func (s *Service) CaptchaEnabled() bool { return len(s.altchaSecret) > 0 }

// SignupInput is POST /auth/signup.
type SignupInput struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	OrgName     string `json:"org_name"`
	// Captcha is the base64 ALTCHA payload (required only when captcha is
	// enabled — the dev bypass is an empty ALTCHA secret).
	Captcha string `json:"captcha"`
	IP      string `json:"-"`
}

// SignupResult is returned to the sign-up handler.
type SignupResult struct {
	User    dbq.User
	Org     dbq.Organisation
	Session Session
}

// Signup validates the captcha and input, then in one transaction creates
// the user, org, owner membership, the trial subscription and the trial
// licence. It enqueues a verification email and returns a pending-setup
// session (owners must enrol TOTP before reaching StageFull).
func (s *Service) Signup(ctx context.Context, in SignupInput) (*SignupResult, error) {
	if s.CaptchaEnabled() {
		if err := s.verifyCaptcha(in.Captcha); err != nil {
			return nil, ErrCaptchaFailed
		}
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if err := validateSignup(email, in.Password, in.OrgName); err != nil {
		return nil, err
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	userID := uuid.Must(uuid.NewV7()).String()
	orgID := uuid.Must(uuid.NewV7()).String()
	now := s.now()
	trialEnd := now.Add(time.Duration(s.trialDays) * 24 * time.Hour)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("signup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)

	if err := q.CreateUser(ctx, dbq.CreateUserParams{
		ID: userID, Email: email, DisplayName: strings.TrimSpace(in.DisplayName),
		PasswordHash: hash,
	}); err != nil {
		if isDup(err) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("signup: create user: %w", err)
	}
	orgName := strings.TrimSpace(in.OrgName)
	if err := q.CreateOrganisation(ctx, dbq.CreateOrganisationParams{
		ID: orgID, Name: orgName, Slug: slugify(orgName, orgID), BillingEmail: email,
	}); err != nil {
		return nil, fmt.Errorf("signup: create org: %w", err)
	}
	if err := q.CreateMembership(ctx, dbq.CreateMembershipParams{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: orgID, UserID: userID, Role: RoleOwner,
	}); err != nil {
		return nil, fmt.Errorf("signup: create membership: %w", err)
	}
	subID := uuid.Must(uuid.NewV7()).String()
	if err := q.CreateSubscription(ctx, dbq.CreateSubscriptionParams{
		ID: subID, OrgID: orgID, Plan: planTrial, Status: statusTrial,
		Seats: 1, CurrentPeriodStart: &now, CurrentPeriodEnd: &trialEnd,
	}); err != nil {
		return nil, fmt.Errorf("signup: create trial subscription: %w", err)
	}
	if err := s.createTrialLicence(ctx, q, orgID, subID, now, trialEnd); err != nil {
		return nil, err
	}
	for _, e := range []audit.Entry{
		{OrgID: orgID, ActorUserID: userID, ActorEmail: email, Action: audit.ActionSignup, TargetType: "user", TargetID: userID, IP: in.IP},
		{OrgID: orgID, ActorUserID: userID, ActorEmail: email, Action: audit.ActionOrgCreated, TargetType: "organisation", TargetID: orgID,
			Detail: map[string]any{"name": orgName, "trial_days": s.trialDays, "trial_max_machines": s.trialMachines}, IP: in.IP},
	} {
		if err := audit.Write(ctx, q, e); err != nil {
			return nil, fmt.Errorf("signup: audit: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("signup: commit: %w", err)
	}

	user, err := s.q.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("signup: reload user: %w", err)
	}
	if err := s.enqueueVerificationMail(ctx, user); err != nil {
		// Sign-up already committed; a lost verification email is
		// recoverable via resend-verification, so log-and-continue.
		s.logEnqueueErr(ctx, "verification", err)
	}
	org, err := s.q.GetOrganisation(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("signup: reload org: %w", err)
	}
	sess, _, err := s.newSessionToken(user, StagePendingSetup)
	if err != nil {
		return nil, err
	}
	return &SignupResult{User: user, Org: org, Session: sess}, nil
}

// createTrialLicence issues the trial licence row (kind=trial,
// max_instances=trial_max_machines) inside the sign-up transaction.
func (s *Service) createTrialLicence(ctx context.Context, q *dbq.Queries, orgID, subID string, issued, expires time.Time) error {
	key := licenceKeyPfx + strings.ToUpper(strings.ReplaceAll(uuid.Must(uuid.NewV7()).String(), "-", ""))
	if err := q.CreateLicence(ctx, dbq.CreateLicenceParams{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: orgID,
		SubscriptionID: sqlNull(subID), LicenceKey: key,
		Kind: "trial", Plan: planTrial, MaxInstances: int32(s.trialMachines),
		IssuedAt: issued, ExpiresAt: &expires,
	}); err != nil {
		return fmt.Errorf("signup: create trial licence: %w", err)
	}
	return nil
}

// LoginInput is POST /auth/login.
type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	IP       string `json:"-"`
}

// LoginResult reports the session stage reached.
type LoginResult struct {
	User    dbq.User
	Session Session
}

// Login verifies the password and returns the session for the stage the
// account needs next: StagePendingTOTP when TOTP is enabled,
// StagePendingSetup when the user owns an org without TOTP enrolled, else
// StageFull.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	u, err := s.q.GetUserByEmail(ctx, email)
	if err != nil || u.DisabledAt != nil || !VerifyPassword(in.Password, u.PasswordHash) {
		_ = audit.Write(ctx, s.q, audit.Entry{
			ActorEmail: email, Action: audit.ActionLoginFailed, TargetType: "user", IP: in.IP,
		})
		return nil, ErrBadCredentials
	}
	stage, err := s.loginStage(ctx, u)
	if err != nil {
		return nil, err
	}
	sess, _, err := s.newSessionToken(u, stage)
	if err != nil {
		return nil, err
	}
	_ = audit.Write(ctx, s.q, audit.Entry{
		ActorUserID: u.ID, ActorEmail: u.Email, Action: audit.ActionLogin,
		TargetType: "user", TargetID: u.ID, Detail: map[string]any{"stage": string(stage)}, IP: in.IP,
	})
	return &LoginResult{User: u, Session: sess}, nil
}

// loginStage picks the post-password stage for u.
func (s *Service) loginStage(ctx context.Context, u dbq.User) (Stage, error) {
	if u.TotpEnabled {
		return StagePendingTOTP, nil
	}
	if u.IsPlatformAdmin {
		return StagePendingSetup, nil // staff must enrol TOTP (R5-5)
	}
	owners, err := s.q.CountUserOwnerOrgs(ctx, u.ID)
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	if owners > 0 {
		return StagePendingSetup, nil // owners must enrol TOTP
	}
	return StageFull, nil
}

// CompleteTOTPLogin finishes a StagePendingTOTP login: verify the code
// against the sealed secret and upgrade the session to StageFull.
func (s *Service) CompleteTOTPLogin(ctx context.Context, sess Session, code, ip string) (Session, error) {
	if sess.Stage != StagePendingTOTP {
		return Session{}, ErrBadToken
	}
	if !s.checkTOTP(ctx, sess.User, code) {
		return Session{}, ErrBadTOTP
	}
	full, _, err := s.newSessionToken(sess.User, StageFull)
	if err != nil {
		return Session{}, err
	}
	_ = audit.Write(ctx, s.q, audit.Entry{
		ActorUserID: sess.User.ID, ActorEmail: sess.User.Email, Action: audit.ActionLogin,
		TargetType: "user", TargetID: sess.User.ID, Detail: map[string]any{"stage": string(StageFull), "totp": true}, IP: ip,
	})
	return full, nil
}

// checkTOTP verifies code against the user's sealed TOTP secret.
func (s *Service) checkTOTP(ctx context.Context, u dbq.User, code string) bool {
	fresh, err := s.q.GetUser(ctx, u.ID)
	if err == nil {
		u = fresh
	}
	if !u.TotpSecretEnc.Valid || len(u.TotpSecretEnc.String) == 0 {
		return false
	}
	secret, err := Open(s.secret, []byte(u.TotpSecretEnc.String))
	if err != nil {
		return false
	}
	return VerifyTOTP(string(secret), code, s.now())
}

// TOTPSetup begins enrolment: a fresh sealed secret (totp_enabled stays 0
// until TOTPEnable verifies a code) and the otpauth URI to render.
func (s *Service) TOTPSetup(ctx context.Context, sess Session) (uri, secret string, err error) {
	raw, err := NewTOTPSecret()
	if err != nil {
		return "", "", err
	}
	sealed, err := Seal(s.secret, []byte(raw))
	if err != nil {
		return "", "", err
	}
	if err := s.q.SetUserTOTPSecret(ctx, dbq.SetUserTOTPSecretParams{
		ID: sess.User.ID, TotpSecretEnc: sqlNullBytes(sealed),
	}); err != nil {
		return "", "", fmt.Errorf("totp setup: %w", err)
	}
	return TOTPProvisioningURI(TOTPIssuer, sess.User.Email, raw), raw, nil
}

// TOTPEnable verifies the enrolment code, flips totp_enabled on and (for
// pending sessions) returns the upgraded StageFull session.
func (s *Service) TOTPEnable(ctx context.Context, sess Session, code, ip string) (Session, error) {
	u, err := s.q.GetUser(ctx, sess.User.ID)
	if err != nil {
		return Session{}, fmt.Errorf("totp enable: %w", err)
	}
	if !u.TotpSecretEnc.Valid || len(u.TotpSecretEnc.String) == 0 {
		return Session{}, ErrTOTPMissing
	}
	secret, err := Open(s.secret, []byte(u.TotpSecretEnc.String))
	if err != nil {
		return Session{}, fmt.Errorf("totp enable: %w", err)
	}
	if !VerifyTOTP(string(secret), code, s.now()) {
		return Session{}, ErrBadTOTP
	}
	if err := s.q.SetUserTOTPEnabled(ctx, dbq.SetUserTOTPEnabledParams{ID: u.ID, TotpEnabled: true}); err != nil {
		return Session{}, fmt.Errorf("totp enable: %w", err)
	}
	_ = audit.Write(ctx, s.q, audit.Entry{
		ActorUserID: u.ID, ActorEmail: u.Email, Action: audit.ActionTOTPEnabled, TargetType: "user", TargetID: u.ID, IP: ip,
	})
	u.TotpEnabled = true
	full, _, err := s.newSessionToken(u, StageFull)
	if err != nil {
		return Session{}, err
	}
	return full, nil
}

// TOTPDisable turns off TOTP after verifying a current code. Owners and
// staff may not disable it (REQUIRED for both).
func (s *Service) TOTPDisable(ctx context.Context, sess Session, code, ip string) error {
	if !s.checkTOTP(ctx, sess.User, code) {
		return ErrBadTOTP
	}
	if sess.User.IsPlatformAdmin {
		return ErrTOTPRequiredStaff
	}
	owners, err := s.q.CountUserOwnerOrgs(ctx, sess.User.ID)
	if err != nil {
		return fmt.Errorf("totp disable: %w", err)
	}
	if owners > 0 {
		return ErrTOTPRequiredOwner
	}
	if err := s.q.SetUserTOTPSecret(ctx, dbq.SetUserTOTPSecretParams{ID: sess.User.ID}); err != nil {
		return fmt.Errorf("totp disable: %w", err)
	}
	if err := s.q.SetUserTOTPEnabled(ctx, dbq.SetUserTOTPEnabledParams{ID: sess.User.ID}); err != nil {
		return fmt.Errorf("totp disable: %w", err)
	}
	_ = audit.Write(ctx, s.q, audit.Entry{
		ActorUserID: sess.User.ID, ActorEmail: sess.User.Email, Action: audit.ActionTOTPDisabled, TargetType: "user", TargetID: sess.User.ID, IP: ip,
	})
	return nil
}

// VerifyEmail consumes a verification token and stamps
// users.email_verified_at (plus the auth.email_verified audit row as
// the event record). Replays are idempotent — a second use of the same
// token is a no-op.
func (s *Service) VerifyEmail(ctx context.Context, token, ip string) error {
	uid, email, err := s.parseVerifyToken(token)
	if err != nil {
		return err
	}
	u, err := s.q.GetUser(ctx, uid)
	if err != nil || u.Email != email {
		return ErrBadToken
	}
	if u.EmailVerifiedAt != nil {
		return nil // already verified — idempotent
	}
	if err := s.q.SetUserEmailVerified(ctx, u.ID); err != nil {
		return fmt.Errorf("verify email: %w", err)
	}
	return audit.Write(ctx, s.q, audit.Entry{
		ActorUserID: u.ID, ActorEmail: u.Email, Action: audit.ActionEmailVerified,
		TargetType: "user", TargetID: u.ID, IP: ip,
	})
}

// EmailVerified reports whether users.email_verified_at is set.
func (s *Service) EmailVerified(ctx context.Context, userID string) (bool, error) {
	u, err := s.q.GetUser(ctx, userID)
	if err != nil {
		return false, err
	}
	return u.EmailVerifiedAt != nil, nil
}

// issueVerifyToken returns the email-verification link token.
func (s *Service) issueVerifyToken(u dbq.User) string {
	exp := s.now().Add(verifyTokenTTL).Unix()
	body := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "v1|%s|%s|%d", u.ID, u.Email, exp))
	return body + "." + s.sign("verify", []byte(body))
}

// parseVerifyToken validates a verification token and returns uid+email.
func (s *Service) parseVerifyToken(token string) (string, string, error) {
	body, sig, ok := cut(token, '.')
	if !ok || s.sign("verify", []byte(body)) != sig {
		return "", "", ErrBadToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", "", ErrBadToken
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != "v1" {
		return "", "", ErrBadToken
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || exp <= s.now().Unix() {
		return "", "", ErrBadToken
	}
	return parts[1], parts[2], nil
}

// ResendVerification enqueues a fresh verification email for the session
// user.
func (s *Service) ResendVerification(ctx context.Context, sess Session) error {
	return s.enqueueVerificationMail(ctx, sess.User)
}

// enqueueVerificationMail composes and queues the verification email.
func (s *Service) enqueueVerificationMail(ctx context.Context, u dbq.User) error {
	if s.queue == nil {
		return nil
	}
	link := s.publicBase + "/verify-email?token=" + s.issueVerifyToken(u)
	_, err := s.queue.Enqueue(ctx, mailer.KindSend, mailer.Message{
		To:      u.Email,
		Subject: "Verify your ServerPerch portal email",
		Text: "Welcome to the ServerPerch customer portal.\n\n" +
			"Confirm this email address within 24 hours by opening:\n\n  " + link +
			"\n\nIf you did not sign up, ignore this message.\n",
		// Dedupe per minute: identical tokens minted in the same window
		// collapse to one mail while real resends still go out.
	}, jobs.WithDedupeKey("verify:"+u.ID+":"+fmt.Sprintf("%d", s.now().Unix()/60)))
	return err
}

// OrgSummary is the small org object embedded in views (sqlc rows have
// no JSON tags — never marshal them directly).
type OrgSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// SubscriptionSummary is the subscription shape the SPA reads.
type SubscriptionSummary struct {
	ID               string     `json:"id"`
	Plan             string     `json:"plan"`
	Status           string     `json:"status"`
	Seats            int32      `json:"seats"`
	CurrentPeriodEnd *time.Time `json:"current_period_end"`
}

func subSummary(s dbq.Subscription) *SubscriptionSummary {
	return &SubscriptionSummary{
		ID: s.ID, Plan: s.Plan, Status: s.Status, Seats: s.Seats,
		CurrentPeriodEnd: s.CurrentPeriodEnd,
	}
}

// OrgView is one org the session user belongs to.
type OrgView struct {
	Org  OrgSummary `json:"org"`
	Role string     `json:"role"`
}

// ListOrgs returns the orgs the user belongs to with their role.
func (s *Service) ListOrgs(ctx context.Context, userID string) ([]OrgView, error) {
	ms, err := s.q.ListUserMemberships(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list orgs: %w", err)
	}
	out := make([]OrgView, 0, len(ms))
	for _, m := range ms {
		org, err := s.q.GetOrganisation(ctx, m.OrgID)
		if err != nil {
			return nil, fmt.Errorf("list orgs: %w", err)
		}
		out = append(out, OrgView{
			Org:  OrgSummary{ID: org.ID, Name: org.Name, Slug: org.Slug},
			Role: m.Role,
		})
	}
	return out, nil
}

// OrgDetail is GET /organisations/{id}.
type OrgDetail struct {
	Org          OrgSummary           `json:"org"`
	Role         string               `json:"role"`
	Subscription *SubscriptionSummary `json:"subscription,omitempty"`
}

// GetOrg returns the org detail for a member; ErrForbidden when the user
// is not a member.
func (s *Service) GetOrg(ctx context.Context, userID, orgID string) (*OrgDetail, error) {
	m, err := s.q.GetMembership(ctx, dbq.GetMembershipParams{OrgID: orgID, UserID: userID})
	if err != nil {
		return nil, ErrForbidden
	}
	org, err := s.q.GetOrganisation(ctx, orgID)
	if err != nil {
		return nil, ErrNotFound
	}
	d := &OrgDetail{
		Org:  OrgSummary{ID: org.ID, Name: org.Name, Slug: org.Slug},
		Role: m.Role,
	}
	if sub, err := s.q.GetLatestSubscriptionByOrg(ctx, orgID); err == nil {
		d.Subscription = subSummary(sub)
	}
	return d, nil
}

// RequireOrgRole checks the session user's role in orgID against the
// allowed set and returns the membership.
func (s *Service) RequireOrgRole(ctx context.Context, userID, orgID string, roles ...string) (dbq.Membership, error) {
	m, err := s.q.GetMembership(ctx, dbq.GetMembershipParams{OrgID: orgID, UserID: userID})
	if err != nil {
		return dbq.Membership{}, ErrForbidden
	}
	for _, r := range roles {
		if m.Role == r {
			return m, nil
		}
	}
	return dbq.Membership{}, ErrForbidden
}

// validateSignup checks the public sign-up fields.
func validateSignup(email, password, orgName string) error {
	var errs []string
	if _, err := mail.ParseAddress(email); err != nil || len(email) > 320 {
		errs = append(errs, "valid email required")
	}
	if l := utf8.RuneCountInString(password); l < minPasswordLen || l > maxPasswordLen {
		errs = append(errs, fmt.Sprintf("password must be %d-%d characters", minPasswordLen, maxPasswordLen))
	}
	if strings.TrimSpace(orgName) == "" || utf8.RuneCountInString(orgName) > 200 {
		errs = append(errs, "organisation name required (max 200 chars)")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrValidation, strings.Join(errs, "; "))
	}
	return nil
}

// slugify derives a DNS-ish slug from the org name, suffixed with the org
// id so collisions are impossible.
func slugify(name, id string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	if slug == "" {
		slug = "org"
	}
	return slug + "-" + strings.ReplaceAll(id, "-", "")[:12]
}

func isDup(err error) bool {
	var merr *gomysql.MySQLError
	return errors.As(err, &merr) && merr.Number == 1062
}

func sqlNull(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func sqlNullBytes(b []byte) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

// audit appends an audit entry attributed to the session user.
func (s *Service) audit(ctx context.Context, sess Session, action, targetType, targetID string, detail any, ip string) error {
	return audit.Write(ctx, s.q, audit.Entry{
		ActorUserID: sess.User.ID, ActorEmail: sess.User.Email, Action: action,
		TargetType: targetType, TargetID: targetID, Detail: detail, IP: ip,
	})
}

// logEnqueueErr records a non-fatal enqueue failure via the audit log's
// error action so silent mail loss is still diagnosable.
func (s *Service) logEnqueueErr(ctx context.Context, what string, cause error) {
	_ = audit.Write(ctx, s.q, audit.Entry{
		Action: "mail.enqueue_failed", TargetType: "mail",
		Detail: map[string]any{"what": what, "error": cause.Error()},
	})
}
