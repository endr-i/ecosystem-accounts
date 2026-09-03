package account

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const (
	maxNameLen = 100
	maxSlugLen = 63
	// autoSlugAttempts bounds the suffix search when deriving a slug from a name.
	autoSlugAttempts = 20
)

var slugRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func validationError(msg string) error {
	return fmt.Errorf("%w: %s", ErrValidation, msg)
}

// Slugify converts an arbitrary name into a URL-safe slug candidate.
func Slugify(s string) string {
	var b strings.Builder
	lastDash := true // suppress leading dashes
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteRune('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > maxSlugLen {
		slug = strings.Trim(slug[:maxSlugLen], "-")
	}
	return slug
}

func ValidateName(name string) error {
	if name == "" {
		return validationError("name is required")
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: name must be at most %d characters", ErrValidation, maxNameLen)
	}
	return nil
}

func ValidateSlug(slug string) error {
	if len(slug) < 2 {
		return validationError("slug must be at least 2 characters")
	}
	if len(slug) > maxSlugLen {
		return fmt.Errorf("%w: slug must be at most %d characters", ErrValidation, maxSlugLen)
	}
	if !slugRe.MatchString(slug) {
		return validationError("slug must contain only lowercase letters, digits and single dashes")
	}
	return nil
}

// Create creates an account owned by userID. When slug is empty it is derived
// from the name, with a numeric suffix appended if needed to stay unique.
func (s *Service) Create(ctx context.Context, userID, name, slug string) (*Account, error) {
	name = strings.TrimSpace(name)
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug != "" {
		if err := ValidateSlug(slug); err != nil {
			return nil, err
		}
		return s.repo.CreateWithOwner(ctx, name, slug, userID)
	}

	base := Slugify(name)
	if err := ValidateSlug(base); err != nil {
		return nil, validationError("could not derive a slug from name, provide one explicitly")
	}

	candidate := base
	for i := 2; ; i++ {
		acc, err := s.repo.CreateWithOwner(ctx, name, candidate, userID)
		if err == nil {
			return acc, nil
		}
		if !errors.Is(err, ErrSlugTaken) || i > autoSlugAttempts {
			return nil, err
		}
		candidate = withSuffix(base, i)
	}
}

// withSuffix appends "-n" to base, trimming base so the result fits maxSlugLen.
func withSuffix(base string, n int) string {
	suffix := fmt.Sprintf("-%d", n)
	if len(base)+len(suffix) > maxSlugLen {
		base = strings.Trim(base[:maxSlugLen-len(suffix)], "-")
	}
	return base + suffix
}

// List returns the accounts the user is a member of.
func (s *Service) List(ctx context.Context, userID string) ([]Membership, error) {
	return s.repo.ListForUser(ctx, userID)
}
