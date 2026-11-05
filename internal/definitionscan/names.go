package definitionscan

import (
	"context"
	"github.com/mtibben/confusables"
	"unicode"
)

// ConfusableNames compares a bounded server's names. Skeletons are transient:
// evidence never includes a name, skeleton or a hash of either.
func ConfusableNames(ctx context.Context, names []string) []bool {
	out := make([]bool, len(names))
	seen := map[string][]int{}
	for i, name := range names {
		if ctx.Err() != nil {
			return out
		}
		if len(name) > MaxBytes {
			continue
		}
		skeleton := confusables.Skeleton(name)
		for _, j := range seen[skeleton] {
			if names[j] != name {
				out[i] = true
				out[j] = true
			}
		}
		seen[skeleton] = append(seen[skeleton], i)
	}
	return out
}

// Resolve common East Asian script combinations, and ignore Common/Inherited
// characters. Script-extension edge cases remain a documented lexical limitation.
func mixedScript(s string) bool {
	scripts := map[string]bool{}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		for name, table := range unicode.Scripts {
			if name != "Common" && name != "Inherited" && unicode.Is(table, r) {
				scripts[name] = true
				break
			}
		}
	}
	if len(scripts) < 2 {
		return false
	}
	for _, allowed := range [][]string{{"Han", "Hiragana", "Katakana"}, {"Han", "Hangul"}, {"Han", "Bopomofo"}} {
		fits := true
		for name := range scripts {
			found := false
			for _, a := range allowed {
				if name == a {
					found = true
				}
			}
			if !found {
				fits = false
			}
		}
		if fits {
			return false
		}
	}
	return true
}
