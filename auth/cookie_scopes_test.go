package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvictedCookieScopes(t *testing.T) {
	assert.Nil(t, EvictedCookieScopes(""))
	assert.Equal(t, []string{""}, EvictedCookieScopes("example.com"))
	assert.Equal(t, []string{"", "example.com"}, EvictedCookieScopes(".app.example.com"))
}
