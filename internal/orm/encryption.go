package orm

import (
	"encoding/json"
	"fmt"
	"time"
)

type EncryptionAlgorithm int

const (
	EncryptionAlgorithmUndefined EncryptionAlgorithm = 0
	EncryptionAlgorithmAES256GCM EncryptionAlgorithm = 1
)

var EncryptionAlgorithmNames = map[EncryptionAlgorithm]string{
	EncryptionAlgorithmUndefined: "undefined",
	EncryptionAlgorithmAES256GCM: "aes-256-gcm",
}

var EncryptionAlgorithmValues = map[string]EncryptionAlgorithm{
	"undefined":   EncryptionAlgorithmUndefined,
	"aes-256-gcm": EncryptionAlgorithmAES256GCM,
}

func (t EncryptionAlgorithm) MarshalJSON() ([]byte, error) {
	s, ok := EncryptionAlgorithmNames[t]
	if !ok {
		return nil, fmt.Errorf("unknown EncryptionAlgorithm %d", t)
	}
	return json.Marshal(s)
}

func (t *EncryptionAlgorithm) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, ok := EncryptionAlgorithmValues[s]
	if !ok {
		return fmt.Errorf("unknown EncryptionAlgorithm %q", s)
	}
	*t = v
	return nil
}

type EncryptionKey struct {
	Id           uint      `gorm:"primaryKey" json:"-"`
	EncryptedDEK string    `gorm:"column:encrypted_dek" json:"encrypted_dek"`
	KekVersion   uint      `gorm:"column:kek_version" json:"kek_version"`
	CreatedAt    time.Time `gorm:"column:created_at" json:"created_at"`
}

func (EncryptionKey) TableName() string {
	return "encryption_keys"
}
