package capture

import (
	"regexp"

	"github.com/ncecere/open-mcp-portal/internal/secretrules"
)

const (
	MaxPartBytes      = secretrules.MaxPartBytes
	Redacted          = secretrules.Redacted
	RuleSensitiveKeys = secretrules.RuleSensitiveKeys
	RuleCallSecrets   = secretrules.RuleCallSecrets
	MaxPatterns       = secretrules.MaxPatterns
	MaxPatternLength  = secretrules.MaxPatternLength
	MaxNoteLength     = secretrules.MaxNoteLength
)

type Rule = secretrules.Rule
type Pattern = secretrules.Pattern
type PatternError = secretrules.PatternError
type Redactor = secretrules.Redactor
type Part = secretrules.Part

// BuiltInRules and SensitiveKeys retain the capture settings catalog.
var BuiltInRules = secretrules.BuiltInRules
var SensitiveKeys = secretrules.SensitiveKeys

func Compile(ps []Pattern) ([]*regexp.Regexp, *PatternError) {
	return secretrules.Compile(ps)
}

func NewRedactor(patterns []*regexp.Regexp, secrets ...string) *Redactor {
	return secretrules.NewRedactor(patterns, secrets...)
}

func Truncate(s string, n int) (string, bool) { return secretrules.Truncate(s, n) }
