package account

import (
	"errors"
	"time"
)

type Status string

const (
	StatusActive    Status = "ACTIVE"
	StatusSuspended Status = "SUSPENDED"
	StatusDeleted   Status = "DELETED"
)

type Role string

const (
	RoleOwner  Role = "OWNER"
	RoleAdmin  Role = "ADMIN"
	RoleMember Role = "MEMBER"
)

type MemberStatus string

const (
	MemberStatusInvited  MemberStatus = "INVITED"
	MemberStatusActive   MemberStatus = "ACTIVE"
	MemberStatusDisabled MemberStatus = "DISABLED"
)

var (
	ErrSlugTaken  = errors.New("slug already taken")
	ErrNotFound   = errors.New("account not found")
	ErrValidation = errors.New("validation error")
)

type Account struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Member struct {
	AccountID string       `json:"account_id"`
	UserID    string       `json:"user_id"`
	Role      Role         `json:"role"`
	Status    MemberStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// Membership pairs an account with the caller's membership in it.
type Membership struct {
	Account
	Role         Role         `json:"role"`
	MemberSince  time.Time    `json:"member_since"`
	MemberStatus MemberStatus `json:"member_status"`
}
