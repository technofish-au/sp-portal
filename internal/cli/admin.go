package cli

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"strings"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/db"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// runAdmin implements `sp-portal admin create --email EMAIL
// [--display-name NAME]`. It creates a staff user (users.is_platform_admin,
// email marked verified — staff do not pass through email verification)
// and prints the generated password once. Staff users carry no org
// membership, so login reaches a full session without TOTP enrolment.
func runAdmin(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "create" {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin: usage: sp-portal admin create --email EMAIL [--display-name NAME]\n")
		return ExitUsage
	}
	var email, displayName string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--email":
			if i+1 >= len(args) {
				_, _ = fmt.Fprintf(stderr, "sp-portal admin create: --email needs a value\n")
				return ExitUsage
			}
			i++
			email = args[i]
		case "--display-name":
			if i+1 >= len(args) {
				_, _ = fmt.Fprintf(stderr, "sp-portal admin create: --display-name needs a value\n")
				return ExitUsage
			}
			i++
			displayName = args[i]
		default:
			_, _ = fmt.Fprintf(stderr, "sp-portal admin create: unknown flag %q\n", args[i])
			return ExitUsage
		}
	}
	if _, err := mail.ParseAddress(email); err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: invalid email %q\n", email)
		return ExitUsage
	}
	cfg, err := loadPortalConfig()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: %v\n", err)
		return ExitUsage
	}
	sqlDB, err := db.Open(ctx, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: %v\n", err)
		return ExitError
	}
	defer func() { _ = sqlDB.Close() }()
	q := dbq.New(sqlDB)

	email = strings.ToLower(strings.TrimSpace(email))
	if _, err := q.GetUserByEmail(ctx, email); err == nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: %s already exists\n", email)
		return ExitError
	} else if !errors.Is(err, sql.ErrNoRows) {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: %v\n", err)
		return ExitError
	}

	password, err := generatedPassword()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: %v\n", err)
		return ExitError
	}
	hash, err := accounts.HashPassword(password)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: %v\n", err)
		return ExitError
	}
	id := uuid.Must(uuid.NewV7()).String()
	if err := q.CreateUser(ctx, dbq.CreateUserParams{
		ID: id, Email: email, DisplayName: strings.TrimSpace(displayName),
		PasswordHash: hash, IsPlatformAdmin: true,
	}); err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: %v\n", err)
		return ExitError
	}
	if err := q.SetUserEmailVerified(ctx, id); err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal admin create: %v\n", err)
		return ExitError
	}
	_, _ = fmt.Fprintf(stdout,
		"Created platform admin %s (id %s).\nPassword: %s\n"+
			"The password is shown only once; sign in at the portal login page.\n",
		email, id, password)
	return ExitOK
}

// generatedPassword returns a 24-char upper-alphanumeric password
// (Crockford-style alphabet without I/L/O/U to keep it unambiguous when
// transcribed).
func generatedPassword() (string, error) {
	const alphabet = "ABCDEFGHJKMNPQRSTVWXYZ0123456789"
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("password: %w", err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}
