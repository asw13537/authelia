package validator

import (
	"fmt"
	"strings"

	"github.com/authelia/authelia/internal/configuration/schema"
)

// ValidateTOTP validates and update TOTP configuration.
func ValidateTOTP(configuration *schema.TOTPConfiguration, validator *schema.StructValidator) {
	if configuration.Issuer == "" {
		configuration.Issuer = schema.DefaultTOTPConfiguration.Issuer
	}

	if configuration.Period == 0 {
		configuration.Period = schema.DefaultTOTPConfiguration.Period
	} else if configuration.Period < 0 {
		validator.Push(fmt.Errorf("TOTP Period must be 1 or more but %d was defined", configuration.Period))
	}

	if configuration.Skew == nil {
		configuration.Skew = schema.DefaultTOTPConfiguration.Skew
	} else if *configuration.Skew < 0 {
		validator.Push(fmt.Errorf("TOTP Skew must be 0 or more but %d was defined", *configuration.Skew))
	}

	configuration.Algorithm = strings.ToLower(configuration.Algorithm)
	if configuration.Algorithm == "" {
		configuration.Algorithm = schema.DefaultTOTPConfiguration.Algorithm
	} else if configuration.Algorithm != sha1 && configuration.Algorithm != sha256 && configuration.Algorithm != sha512 {
		validator.Push(fmt.Errorf("TOTP Algorithm must be one of %s, %s, or %s but %s was defined", sha1, sha256, sha512, configuration.Algorithm))
	}
}
