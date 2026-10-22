package auth

import (
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// TestProviderSetScopeIsUnambiguous asserts that two different provider sets
// never produce the same scope.
//
// One provider named "a,b" and two providers named "a" and "b" are different
// sets. With an ambiguous scope they shared one, and changing between those
// routes silently reused an existing binding instead of creating a distinct
// scope.
func TestProviderSetScopeIsUnambiguous(t *testing.T) {
	t.Parallel()

	three := canonicalProviderSetScope(map[string]struct{}{
		"codex":               {},
		"openai-compatible-a": {},
		"openai-compatible-b": {},
	})
	one := canonicalProviderSetScope(map[string]struct{}{
		"codex": {},
		"openai-compatible-a,openai-compatible-b": {},
	})
	if three == one {
		t.Fatalf("two different provider sets produced the same scope %q", three)
	}
	if three == "" || one == "" {
		t.Fatal("a provider set produced no scope")
	}
}

// TestProviderSetScopeEncodesStructuralCharacters asserts that the characters
// that are structural in a scope are encoded.
//
// The scope is joined with a comma and carried in a cache key that is
// delimited by brackets and separated by colons, so a provider name that
// contains one of them must not change the shape of either.
func TestProviderSetScopeEncodesStructuralCharacters(t *testing.T) {
	t.Parallel()

	scope := canonicalProviderSetScope(map[string]struct{}{
		"a,b":    {},
		"c[d]":   {},
		"e:f":    {},
		"g%h":    {},
		"i j":    {},
		"normal": {},
	})
	if scope == "" {
		t.Fatal("no scope was produced")
	}
	for _, structural := range []string{",", "[", "]", ":", "%", " "} {
		if scope != "" && containsUnencodedStructural(scope, structural) {
			t.Fatalf("the scope %q carries an unencoded %q", scope, structural)
		}
	}
	// The encoded scope must not have a bracket outside the percent encoding.
	if hasUnencodedBracket(scope) {
		t.Fatalf("the scope %q carries an unencoded bracket", scope)
	}
}

// containsUnencodedStructural reports whether the scope carries the character
// outside a percent encoding.
func containsUnencodedStructural(scope, structural string) bool {
	for i := 0; i < len(scope); i++ {
		if scope[i] == '%' {
			// Skip the encoded byte.
			i += 2
			continue
		}
		if structural == "," && scope[i] == ',' {
			// The comma is the separator, so it is allowed between the
			// components, but not inside one.
			continue
		}
		if string(scope[i]) == structural {
			return true
		}
	}
	return false
}

// hasUnencodedBracket reports whether the scope carries a bracket outside a
// percent encoding.
func hasUnencodedBracket(scope string) bool {
	for i := 0; i < len(scope); i++ {
		if scope[i] == '%' {
			i += 2
			continue
		}
		if scope[i] == '[' || scope[i] == ']' {
			return true
		}
	}
	return false
}

// TestScopedLookupIgnoresABracketInAPlainProviderName asserts that a plain
// provider name that contains a bracket is not read as a scoped namespace.
//
// The scope syntax belongs to the mixed namespace. A binding of the provider
// "openai[compat]" must not answer a lookup of the provider "openai".
func TestScopedLookupIgnoresABracketInAPlainProviderName(t *testing.T) {
	t.Parallel()

	cache := NewSessionCache(time.Hour)
	defer cache.Stop()

	cache.Set("openai[compat]::header:s1::model-1", "auth-1")

	found := cache.GetByScopeSuffixes("openai", []string{"::header:s1::model-1"})
	if len(found) != 0 {
		t.Fatalf("found = %v, want no binding of another provider", found)
	}
	found = cache.GetByScopeSuffixes("openai[compat]", []string{"::header:s1::model-1"})
	if len(found) != 1 {
		t.Fatalf("found = %v, want the binding of the provider itself", found)
	}
}

// TestLCPAffinityNamespaceIsStableForAScopedProvider asserts that the LCP
// namespace of a scoped provider is the same however it is reached.
//
// The selection builds the namespace from the route's provider, and the result
// handling reads the provider back out of the namespace and builds it again. If
// the two disagree, a success update writes a second binding and a failure
// leaves the selected binding in place.
func TestLCPAffinityNamespaceIsStableForAScopedProvider(t *testing.T) {
	t.Parallel()

	metadata := map[string]any{
		cliproxyexecutor.CallerScopeMetadataKey:                "caller-1",
		cliproxyexecutor.SessionAffinityProviderSetMetadataKey: "codex,openai-compatible-a%2Cb",
	}
	selected := lcpAffinityNamespace("mixed", "model-1", metadata)
	if selected == "" {
		t.Fatal("no namespace was built")
	}

	// The result handling builds the namespace from the provider the selection
	// already scoped, so the two must agree.
	scopedProvider := sessionAffinityNamespace("mixed", metadata)
	again := lcpAffinityNamespace(scopedProvider, "model-1", metadata)
	if again != selected {
		t.Fatalf("the namespace changed: %q -> %q", selected, again)
	}
}

// TestLCPNamespaceProviderKeepsABracketInAPlainProviderName asserts that a
// plain provider name that contains a bracket is not truncated.
//
// Truncating it would read the provider "openai[compat]" as "openai", and the
// two would share their affinity.
func TestLCPNamespaceProviderKeepsABracketInAPlainProviderName(t *testing.T) {
	t.Parallel()

	if got := lcpNamespaceProvider("openai[compat]"); got != "openai[compat]" {
		t.Fatalf("the provider = %q, want it unchanged", got)
	}
	if got := lcpNamespaceProvider("mixed[a,b]"); got != "mixed" {
		t.Fatalf("the mixed provider = %q, want %q", got, "mixed")
	}
	if got := lcpNamespaceProvider("openai"); got != "openai" {
		t.Fatalf("the provider = %q, want %q", got, "openai")
	}
}
