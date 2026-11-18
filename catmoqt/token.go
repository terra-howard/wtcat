package catmoqt

import (
	"errors"
	"fmt"
)

// The Alias Types of a Token structure.
const (
	aliasDelete   = 0
	aliasRegister = 1
	aliasUse      = 2
	aliasValue    = 3
)

// TokenTypeCAT is the Auth Token Type of a Common Access Token (draft-ietf-moq-c4m).
const TokenTypeCAT = 0x01

// Token is a token as a Token structure carries it, or as the cache holds it: its Auth Token Type and its value.
type Token struct {
	Type  uint64
	Value []byte
}

// tokenStructure is a decoded Token structure.
type tokenStructure struct {
	aliasType uint64
	alias     uint64
	token     Token
}

// parseToken decodes a Token structure: an Alias Type, then an alias for DELETE, REGISTER and USE_ALIAS, then a
// Token Type and the Token Value, which is the rest, for REGISTER and USE_VALUE.
func parseToken(b []byte) (tokenStructure, error) {
	var t tokenStructure
	var err error
	if t.aliasType, b, err = readVarint(b); err != nil {
		return t, err
	}
	if t.aliasType > aliasValue {
		return t, fmt.Errorf("Alias Type %d", t.aliasType)
	}
	if t.aliasType != aliasValue {
		if t.alias, b, err = readVarint(b); err != nil {
			return t, err
		}
	}
	if t.aliasType == aliasDelete || t.aliasType == aliasUse {
		if len(b) != 0 {
			return t, errors.New("a DELETE or USE_ALIAS with a Token Type or Value")
		}
		return t, nil
	}
	if t.token.Type, b, err = readVarint(b); err != nil {
		return t, err
	}
	t.token.Value = b
	return t, nil
}
