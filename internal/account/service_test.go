package account

import (
	"errors"
	"strings"
	"testing"
)

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Acme Corp":         "acme-corp",
		"  Hello   World  ": "hello-world",
		"Foo_Bar/Baz":       "foo-bar-baz",
		"---dashes---":      "dashes",
		"MiXeD CaSe 123":    "mixed-case-123",
		"!!!":               "",
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSlugifyTruncates(t *testing.T) {
	got := Slugify(strings.Repeat("a", 200))
	if len(got) != maxSlugLen {
		t.Fatalf("len = %d, want %d", len(got), maxSlugLen)
	}
}

func TestValidateSlug(t *testing.T) {
	valid := []string{"acme", "acme-corp", "a1-b2-c3"}
	for _, s := range valid {
		if err := ValidateSlug(s); err != nil {
			t.Errorf("ValidateSlug(%q) = %v, want nil", s, err)
		}
	}
	invalid := []string{"", "a", "Acme", "acme_corp", "-acme", "acme-", "acme--corp", strings.Repeat("a", 64)}
	for _, s := range invalid {
		if err := ValidateSlug(s); !errors.Is(err, ErrValidation) {
			t.Errorf("ValidateSlug(%q) = %v, want ErrValidation", s, err)
		}
	}
}

func TestValidateName(t *testing.T) {
	if err := ValidateName("Acme"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateName(""); !errors.Is(err, ErrValidation) {
		t.Errorf("empty name = %v, want ErrValidation", err)
	}
	if err := ValidateName(strings.Repeat("a", maxNameLen+1)); !errors.Is(err, ErrValidation) {
		t.Errorf("long name = %v, want ErrValidation", err)
	}
}

func TestWithSuffix(t *testing.T) {
	if got := withSuffix("acme", 2); got != "acme-2" {
		t.Errorf("withSuffix = %q, want acme-2", got)
	}
	long := strings.Repeat("a", maxSlugLen)
	got := withSuffix(long, 10)
	if len(got) != maxSlugLen {
		t.Errorf("len = %d, want %d", len(got), maxSlugLen)
	}
	if err := ValidateSlug(got); err != nil {
		t.Errorf("ValidateSlug(%q) = %v", got, err)
	}
}
