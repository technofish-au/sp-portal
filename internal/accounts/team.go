// Team management (R5-5): org member invites, role changes, removal and
// the per-user notification preferences the portal pages edit.
//
// Invites create the user row immediately (empty password_hash —
// password login fails until the invite is accepted) plus the
// membership, then email an "invite" signed token that the
// /auth/accept-invite endpoint exchanges for a password + session.
package accounts

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/mailer"
)

// inviteTokenTTL bounds the accept-invite link.
const inviteTokenTTL = 7 * 24 * time.Hour

// memberRoles is the assignable role set (memberships_role_check).
var memberRoles = map[string]bool{
	RoleOwner: true, RoleAdmin: true, RoleMember: true, RoleViewer: true,
}

// memberView is the public member row (id/email/display_name/role).
func memberView(m dbq.ListOrgMembersRow) map[string]any {
	return map[string]any{
		"id":           m.ID,
		"email":        m.Email,
		"display_name": m.DisplayName,
		"role":         m.Role,
	}
}

// NotificationPrefs is the per-user, per-org email opt-out set
// (notification_prefs row; a missing row means all defaults on).
// Billing mail is never opt-out — SetNotificationPrefs forces it on.
type NotificationPrefs struct {
	VersionBehind   bool `json:"notify_version_behind"`
	SecurityRelease bool `json:"notify_security_release"`
	LicenceExpiry   bool `json:"notify_licence_expiry"`
	Billing         bool `json:"notify_billing"`
}

// InviteMember adds email to the org: the membership is created at once
// and the invite email carries the signed accept token. Role must come
// from memberRoles; the caller must hold owner or admin.
func (s *Service) InviteMember(ctx context.Context, sess Session, orgID, email, displayName, role, ip string) (*OrgDetail, error) {
	if _, err := s.RequireOrgRole(ctx, sess.User.ID, orgID, RoleOwner, RoleAdmin); err != nil {
		return nil, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, fmt.Errorf("%w: invalid email", ErrValidation)
	}
	if !memberRoles[role] {
		return nil, fmt.Errorf("%w: role must be owner, admin, member or viewer", ErrValidation)
	}
	org, err := s.q.GetOrganisation(ctx, orgID)
	if err != nil {
		return nil, ErrNotFound
	}

	u, err := s.q.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		u = dbq.User{ID: uuid.Must(uuid.NewV7()).String(), Email: email}
		if err := s.q.CreateUser(ctx, dbq.CreateUserParams{
			ID: u.ID, Email: email, DisplayName: strings.TrimSpace(displayName),
		}); err != nil {
			return nil, fmt.Errorf("invite: create user: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("invite: user lookup: %w", err)
	}
	if _, err := s.q.GetMembership(ctx, dbq.GetMembershipParams{OrgID: orgID, UserID: u.ID}); err == nil {
		return nil, ErrAlreadyMember
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("invite: membership lookup: %w", err)
	}
	if err := s.q.CreateMembership(ctx, dbq.CreateMembershipParams{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: orgID, UserID: u.ID, Role: role,
	}); err != nil {
		return nil, fmt.Errorf("invite: membership: %w", err)
	}
	if err := audit.Write(ctx, s.q, audit.Entry{
		OrgID: orgID, ActorUserID: sess.User.ID, ActorEmail: sess.User.Email,
		Action: audit.ActionMemberInvited, TargetType: "user", TargetID: u.ID,
		Detail: map[string]any{"email": email, "role": role}, IP: ip,
	}); err != nil {
		return nil, fmt.Errorf("invite: audit: %w", err)
	}
	if err := s.enqueueInviteMail(ctx, org, u); err != nil {
		s.logEnqueueErr(ctx, "invite", err)
	}
	return &OrgDetail{
		Org:  OrgSummary{ID: org.ID, Name: org.Name, Slug: org.Slug},
		Role: role,
	}, nil
}

// issueInviteToken returns the accept-invite link token for u.
func (s *Service) issueInviteToken(u dbq.User) string {
	exp := s.now().Add(inviteTokenTTL).Unix()
	body := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "i1|%s|%s|%d", u.ID, u.Email, exp))
	return body + "." + s.sign("invite", []byte(body))
}

// parseInviteToken validates an invite token and returns uid+email.
func (s *Service) parseInviteToken(token string) (string, string, error) {
	body, sig, ok := cut(token, '.')
	if !ok || s.sign("invite", []byte(body)) != sig {
		return "", "", ErrBadToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", "", ErrBadToken
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != "i1" {
		return "", "", ErrBadToken
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || exp <= s.now().Unix() {
		return "", "", ErrBadToken
	}
	return parts[1], parts[2], nil
}

// AcceptInvite consumes an invite token. A fresh user (no password yet)
// must supply one; an existing account's token is a no-op beyond
// confirming the invite. Returns the full session to set on success.
func (s *Service) AcceptInvite(ctx context.Context, token, password, displayName, ip string) (Session, bool, error) {
	uid, email, err := s.parseInviteToken(token)
	if err != nil {
		return Session{}, false, err
	}
	u, err := s.q.GetUser(ctx, uid)
	if err != nil || u.Email != email {
		return Session{}, false, ErrBadToken
	}
	if u.PasswordHash != "" {
		// The account already has credentials — invite is a no-op past
		// this point (the membership was created when it was sent).
		sess, _, err := s.newSessionToken(u, StageFull)
		return sess, true, err
	}
	if l := utf8.RuneCountInString(password); l < minPasswordLen || l > maxPasswordLen {
		return Session{}, false, fmt.Errorf("%w: password must be %d-%d characters", ErrValidation, minPasswordLen, maxPasswordLen)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return Session{}, false, err
	}
	if err := s.q.UpdateUserPassword(ctx, dbq.UpdateUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		return Session{}, false, fmt.Errorf("accept invite: %w", err)
	}
	if name := strings.TrimSpace(displayName); name != "" {
		if err := s.q.SetUserDisplayName(ctx, dbq.SetUserDisplayNameParams{ID: u.ID, DisplayName: name}); err != nil {
			return Session{}, false, fmt.Errorf("accept invite: %w", err)
		}
		u.DisplayName = name
	}
	if err := s.q.SetUserEmailVerified(ctx, u.ID); err != nil {
		return Session{}, false, fmt.Errorf("accept invite: %w", err)
	}
	_ = audit.Write(ctx, s.q, audit.Entry{
		ActorUserID: u.ID, ActorEmail: u.Email, Action: audit.ActionInviteAccepted,
		TargetType: "user", TargetID: u.ID, IP: ip,
	})
	u, err = s.q.GetUser(ctx, u.ID)
	if err != nil {
		return Session{}, false, fmt.Errorf("accept invite: %w", err)
	}
	sess, _, err := s.newSessionToken(u, StageFull)
	return sess, false, err
}

// SetMemberRole changes a member's role; owner/admin callers only and the
// org's last owner may not be demoted.
func (s *Service) SetMemberRole(ctx context.Context, sess Session, orgID, userID, role, ip string) error {
	if _, err := s.RequireOrgRole(ctx, sess.User.ID, orgID, RoleOwner, RoleAdmin); err != nil {
		return err
	}
	if !memberRoles[role] {
		return fmt.Errorf("%w: role must be owner, admin, member or viewer", ErrValidation)
	}
	target, err := s.q.GetMembership(ctx, dbq.GetMembershipParams{OrgID: orgID, UserID: userID})
	if err != nil {
		return ErrNotFound
	}
	if target.Role == RoleOwner && role != RoleOwner {
		owners, err := s.q.CountOrgOwners(ctx, orgID)
		if err != nil {
			return fmt.Errorf("member role: %w", err)
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}
	if target.Role == role {
		return nil // no-op
	}
	if err := s.q.UpdateMembershipRole(ctx, dbq.UpdateMembershipRoleParams{
		OrgID: orgID, UserID: userID, Role: role,
	}); err != nil {
		return fmt.Errorf("member role: %w", err)
	}
	return audit.Write(ctx, s.q, audit.Entry{
		OrgID: orgID, ActorUserID: sess.User.ID, ActorEmail: sess.User.Email,
		Action: audit.ActionMemberRoleSet, TargetType: "user", TargetID: userID,
		Detail: map[string]any{"from": target.Role, "to": role}, IP: ip,
	})
}

// RemoveMember drops a membership; owner/admin callers only and the
// org's last owner may not be removed.
func (s *Service) RemoveMember(ctx context.Context, sess Session, orgID, userID, ip string) error {
	if _, err := s.RequireOrgRole(ctx, sess.User.ID, orgID, RoleOwner, RoleAdmin); err != nil {
		return err
	}
	target, err := s.q.GetMembership(ctx, dbq.GetMembershipParams{OrgID: orgID, UserID: userID})
	if err != nil {
		return ErrNotFound
	}
	if target.Role == RoleOwner {
		owners, err := s.q.CountOrgOwners(ctx, orgID)
		if err != nil {
			return fmt.Errorf("member remove: %w", err)
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}
	if err := s.q.DeleteMembership(ctx, dbq.DeleteMembershipParams{OrgID: orgID, UserID: userID}); err != nil {
		return fmt.Errorf("member remove: %w", err)
	}
	return audit.Write(ctx, s.q, audit.Entry{
		OrgID: orgID, ActorUserID: sess.User.ID, ActorEmail: sess.User.Email,
		Action: audit.ActionMemberRemoved, TargetType: "user", TargetID: userID,
		Detail: map[string]any{"role": target.Role}, IP: ip,
	})
}

// NotificationPrefsFor returns the member's prefs (defaults when unset).
func (s *Service) NotificationPrefsFor(ctx context.Context, sess Session, orgID string) (NotificationPrefs, error) {
	if _, err := s.RequireOrgRole(ctx, sess.User.ID, orgID, RoleOwner, RoleAdmin, RoleMember, RoleViewer); err != nil {
		return NotificationPrefs{}, err
	}
	row, err := s.q.GetNotificationPrefs(ctx, dbq.GetNotificationPrefsParams{OrgID: orgID, UserID: sess.User.ID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return NotificationPrefs{VersionBehind: true, SecurityRelease: true, LicenceExpiry: true, Billing: true}, nil
		}
		return NotificationPrefs{}, fmt.Errorf("notification prefs: %w", err)
	}
	return NotificationPrefs{
		VersionBehind:   row.NotifyVersionBehind,
		SecurityRelease: row.NotifySecurityRelease,
		LicenceExpiry:   row.NotifyLicenceExpiry,
		Billing:         true, // never opt-out regardless of stored value
	}, nil
}

// SetNotificationPrefs upserts the member's prefs; billing is forced on.
func (s *Service) SetNotificationPrefs(ctx context.Context, sess Session, orgID string, p NotificationPrefs, ip string) error {
	if _, err := s.RequireOrgRole(ctx, sess.User.ID, orgID, RoleOwner, RoleAdmin, RoleMember, RoleViewer); err != nil {
		return err
	}
	p.Billing = true
	if err := s.q.UpsertNotificationPrefs(ctx, dbq.UpsertNotificationPrefsParams{
		OrgID: orgID, UserID: sess.User.ID,
		NotifyVersionBehind:   p.VersionBehind,
		NotifySecurityRelease: p.SecurityRelease,
		NotifyLicenceExpiry:   p.LicenceExpiry,
		NotifyBilling:         true,
	}); err != nil {
		return fmt.Errorf("notification prefs: %w", err)
	}
	return audit.Write(ctx, s.q, audit.Entry{
		OrgID: orgID, ActorUserID: sess.User.ID, ActorEmail: sess.User.Email,
		Action: audit.ActionNotifPrefs, TargetType: "organisation", TargetID: orgID, IP: ip,
	})
}

// enqueueInviteMail composes and queues the invite email; a nil queue
// (tests) is a no-op.
func (s *Service) enqueueInviteMail(ctx context.Context, org dbq.Organisation, u dbq.User) error {
	if s.queue == nil {
		return nil
	}
	link := s.publicBase + "/accept-invite?token=" + s.issueInviteToken(u)
	_, err := s.queue.Enqueue(ctx, mailer.KindSend, mailer.Message{
		To:      u.Email,
		Subject: "You've been invited to " + org.Name + " on ServerPerch",
		Text: "The " + org.Name + " team invited you to the ServerPerch customer portal.\n\n" +
			"Accept the invite within 7 days by opening:\n\n  " + link +
			"\n\nIf you already have an account the link simply confirms the invite.\n",
	}, jobs.WithDedupeKey("invite:"+org.ID+":"+u.ID))
	return err
}

// --- handlers ------------------------------------------------------------

func (s *Service) handleInviteMember(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	var in struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	d, err := s.InviteMember(r.Context(), sess, chi.URLParam(r, "orgID"), in.Email, in.DisplayName, in.Role, clientIP(r))
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "invited",
		"org":    map[string]any{"id": d.Org.ID, "name": d.Org.Name},
		"role":   d.Role,
	})
}

func (s *Service) handleAcceptInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token       string `json:"token"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	sess, existing, err := s.AcceptInvite(r.Context(), in.Token, in.Password, in.DisplayName, clientIP(r))
	if err != nil {
		apiErr(w, err)
		return
	}
	s.setSessionCookie(w, mustEncode(s, sess), sess.Expires)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"existing": existing,
	})
}

func (s *Service) handleUpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	var in struct {
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	err := s.SetMemberRole(r.Context(), sess, chi.URLParam(r, "orgID"), chi.URLParam(r, "userID"), in.Role, clientIP(r))
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	err := s.RemoveMember(r.Context(), sess, chi.URLParam(r, "orgID"), chi.URLParam(r, "userID"), clientIP(r))
	if err != nil {
		apiErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleGetNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	prefs, err := s.NotificationPrefsFor(r.Context(), sess, chi.URLParam(r, "orgID"))
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prefs": prefs})
}

func (s *Service) handlePutNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	var in NotificationPrefs
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.SetNotificationPrefs(r.Context(), sess, chi.URLParam(r, "orgID"), in, clientIP(r)); err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prefs": in})
}
