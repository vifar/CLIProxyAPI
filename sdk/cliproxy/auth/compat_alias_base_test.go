package auth

import (
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// TestCompatAliasBaseIsRoutedToTheConfiguredModel asserts that a request for the
// base of a configured alias reaches the configured model.
//
// The alias table the manager builds for an API-key credential holds the base of
// every configured alias, so a request for "model-b" is routed to the model the
// operator aliased as "model-b(high)". A live model of that name would then be
// published but never routed to, so the catalog reserves the base name.
func TestCompatAliasBaseIsRoutedToTheConfiguredModel(t *testing.T) {
	t.Parallel()

	byAlias := map[string]string{}
	compileAPIKeyModelAliasForModels(byAlias, []internalconfig.OpenAICompatibilityModel{
		{Name: "model-x", Alias: "model-b(high)"},
	})

	if got := byAlias["model-b"]; got != "model-x" {
		t.Fatalf("the base of the alias resolves to %q, want model-x: %v", got, byAlias)
	}
	if got := byAlias["model-b(high)"]; got != "model-x" {
		t.Fatalf("the alias resolves to %q, want model-x: %v", got, byAlias)
	}
}

// TestMergeCompatCatalogModelsReservesTheAliasBase asserts that a live model
// whose name is the base of a configured alias is not published.
//
// The request for that name is routed to the configured model, so publishing the
// live model would offer a name that never reaches it.
func TestMergeCompatCatalogModelsReservesTheAliasBase(t *testing.T) {
	t.Parallel()

	merged := internalconfig.MergeCompatCatalogModels(
		[]internalconfig.OpenAICompatibilityModel{{Name: "model-x", Alias: "model-b(high)"}},
		[]internalconfig.CompatCatalogModel{{ID: "model-b"}, {ID: "model-y"}},
		nil,
	)
	published := make(map[string]struct{}, len(merged))
	for _, model := range merged {
		published[model.Alias] = struct{}{}
	}
	if _, ok := published["model-b"]; ok {
		t.Fatalf("the base of the alias was published: %v", published)
	}
	if _, ok := published["model-y"]; !ok {
		t.Fatalf("the distinct live model was not published: %v", published)
	}
}
