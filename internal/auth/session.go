package auth

import (
	"fmt"
	"time"

	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type SessionTokens struct {
	SessionToken string
	RefreshToken string
}

func NewSession(db *gorm.DB, u *orm.User) (*SessionTokens, error) {
	raw, err := GenerateToken()
	if err != nil {
		return nil, err
	}
	st := SessionPrefix + raw

	raw, err = GenerateToken()
	if err != nil {
		return nil, err
	}
	rt := RefreshPrefix + raw

	s := orm.Session{
		UserId:           u.Id,
		TokenHash:        HashToken(st),
		RefreshTokenHash: HashToken(rt),
		ExpiresAt:        time.Now().Add(15 * time.Minute),
	}
	if err := store.CreateSession(db, &s); err != nil {
		return nil, err
	}

	return &SessionTokens{SessionToken: st, RefreshToken: rt}, nil
}

func Login(db *gorm.DB, username string, password string) (*SessionTokens, error) {
	u, err := store.GetUser(db, username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.Pass), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return NewSession(db, u)
}

func Refresh(db *gorm.DB, refreshToken string) (*SessionTokens, error) {
	session, err := store.GetSessionByRefreshTokenHash(db, HashToken(refreshToken))
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("invalid token")
	}

	u, err := store.GetUserById(db, session.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	tokens, err := NewSession(db, u)
	if err != nil {
		return nil, err
	}

	if err := store.DeleteSession(db, session.Id); err != nil {
		return nil, err
	}

	return tokens, nil
}

func Logout(db *gorm.DB, sessionToken string) error {
	session, err := store.GetSessionByTokenHash(db, HashToken(sessionToken))
	if err != nil {
		return fmt.Errorf("invalid token")
	}
	return store.InvalidateSession(db, session.Id)
}
