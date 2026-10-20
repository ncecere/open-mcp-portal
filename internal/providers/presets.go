package providers

// Presets only pre-fill the create form; a provider stores whatever is sent.
// The values were checked against each provider's documentation (and, where
// published, its OpenID configuration) in October 2026; see
// docs/phase5-delegated-credentials.md "As built".

// URLParameter is a placeholder in a preset's URLs ({tenant}, {host}).
type URLParameter struct {
	Name, Label string
	Default     *string
}

// Preset is a starting point for a common provider.
type Preset struct {
	Preset, Name                           string
	AuthorizationURL, TokenURL             string
	RevocationURL, UserinfoURL             *string
	DefaultScopes                          []string
	TokenAuthMethod                        string
	PKCE                                   bool
	ScopeParam, ScopeSeparator, RespFormat string
	ExtraParams                            map[string]string
	URLParameters                          []URLParameter
	DocsURL, Notes                         string
	// NarrowOnRefresh pre-fills the narrowing switch (decision 69): true only
	// where the provider's own documentation says a refresh request's scope
	// parameter narrows the new access token. Documentation is what was
	// checked (October 2026), not a live account; see
	// docs/phase5-delegated-credentials.md "Which servers and scopes are sent".
	NarrowOnRefresh bool
}

func str(s string) *string { return &s }

// Presets are the built-in presets, in display order.
var Presets = []Preset{
	{
		Preset: "github", Name: "GitHub",
		AuthorizationURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token",
		UserinfoURL: str("https://api.github.com/user"), DefaultScopes: []string{"read:user"},
		TokenAuthMethod: AuthClientSecretPost, PKCE: true, ScopeParam: "scope", ScopeSeparator: " ", RespFormat: FormatStandard,
		ExtraParams: map[string]string{}, URLParameters: []URLParameter{},
		DocsURL: "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app",
		Notes: "OAuth app tokens don't expire unless the app opts into expiring tokens. GitHub has no RFC 7009 revocation " +
			"endpoint: disconnecting erases the token here only (people can revoke the app in their GitHub settings). " +
			"Scopes come back comma-separated, which the portal understands. No refresh with a narrower scope " +
			"(GitHub documents none): narrowing stays off.",
	},
	{
		Preset: "google", Name: "Google",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
		RevocationURL: str("https://oauth2.googleapis.com/revoke"), UserinfoURL: str("https://openidconnect.googleapis.com/v1/userinfo"),
		DefaultScopes:   []string{"openid", "https://www.googleapis.com/auth/userinfo.email"},
		TokenAuthMethod: AuthClientSecretPost, PKCE: true, ScopeParam: "scope", ScopeSeparator: " ", RespFormat: FormatStandard,
		ExtraParams:   map[string]string{"access_type": "offline", "prompt": "consent", "include_granted_scopes": "true"},
		URLParameters: []URLParameter{},
		DocsURL:       "https://developers.google.com/identity/protocols/oauth2/web-server",
		Notes: "Use full scope URLs (https://www.googleapis.com/auth/...), as Google reports them. access_type=offline " +
			"and prompt=consent make Google return a refresh token. Google documents no scope parameter on refresh: " +
			"narrowing stays off.",
	},
	{
		Preset: "microsoft", Name: "Microsoft Entra ID",
		AuthorizationURL: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
		UserinfoURL:      str("https://graph.microsoft.com/oidc/userinfo"),
		DefaultScopes:    []string{"openid", "profile", "email", "offline_access", "User.Read"},
		TokenAuthMethod:  AuthClientSecretPost, PKCE: true, ScopeParam: "scope", ScopeSeparator: " ", RespFormat: FormatStandard,
		ExtraParams:     map[string]string{},
		NarrowOnRefresh: true,
		URLParameters:   []URLParameter{{Name: "tenant", Label: "Directory (tenant) ID, or organizations", Default: str("organizations")}},
		DocsURL:         "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow",
		Notes: "offline_access is needed for a refresh token. A token is for one resource: keep Microsoft Graph scopes " +
			"together. Entra ID has no RFC 7009 revocation endpoint. Microsoft documents that a refresh request's scope " +
			"may be a subset of the granted scopes, so narrowing is pre-filled on (checked against the documentation, " +
			"not a live tenant); a token is issued for the resource of the first scope.",
	},
	{
		Preset: "atlassian", Name: "Atlassian",
		AuthorizationURL: "https://auth.atlassian.com/authorize", TokenURL: "https://auth.atlassian.com/oauth/token",
		UserinfoURL: str("https://api.atlassian.com/me"), DefaultScopes: []string{"read:me", "offline_access"},
		TokenAuthMethod: AuthClientSecretPost, PKCE: false, ScopeParam: "scope", ScopeSeparator: " ", RespFormat: FormatStandard,
		ExtraParams:   map[string]string{"audience": "api.atlassian.com", "prompt": "consent"},
		URLParameters: []URLParameter{},
		DocsURL:       "https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/",
		Notes: "Add the User Identity API to the app for read:me. Refresh tokens rotate and expire after 90 days " +
			"unused. Atlassian has no RFC 7009 revocation endpoint. Atlassian documents no scope parameter on refresh: " +
			"narrowing stays off.",
	},
	{
		Preset: "slack", Name: "Slack",
		AuthorizationURL: "https://slack.com/oauth/v2/authorize", TokenURL: "https://slack.com/api/oauth.v2.access",
		DefaultScopes:   []string{"users:read"},
		TokenAuthMethod: AuthClientSecretPost, PKCE: false, ScopeParam: "user_scope", ScopeSeparator: ",", RespFormat: FormatSlackAuthedUser,
		ExtraParams: map[string]string{}, URLParameters: []URLParameter{},
		DocsURL: "https://docs.slack.dev/authentication/installing-with-oauth",
		Notes: "User tokens: scopes go in user_scope (comma-separated) and the token comes back under authed_user. " +
			"Tokens don't expire unless the app turns on token rotation. Slack revokes with auth.revoke, not RFC 7009. " +
			"Slack documents no scope parameter on refresh: narrowing stays off.",
	},
	{
		Preset: "gitlab", Name: "GitLab",
		AuthorizationURL: "https://{host}/oauth/authorize", TokenURL: "https://{host}/oauth/token",
		RevocationURL: str("https://{host}/oauth/revoke"), UserinfoURL: str("https://{host}/oauth/userinfo"),
		DefaultScopes:   []string{"openid", "read_user"},
		TokenAuthMethod: AuthClientSecretPost, PKCE: true, ScopeParam: "scope", ScopeSeparator: " ", RespFormat: FormatStandard,
		ExtraParams:   map[string]string{},
		URLParameters: []URLParameter{{Name: "host", Label: "GitLab host (gitlab.com, or your self-managed instance)", Default: str("gitlab.com")}},
		DocsURL:       "https://docs.gitlab.com/integration/oauth_provider/",
		Notes: "Access tokens expire after two hours and refresh tokens rotate. openid is needed for the userinfo endpoint. " +
			"GitLab's documentation shows no scope parameter on refresh (its OAuth library, Doorkeeper, accepts one in its " +
			"current source, but this was not confirmed for GitLab's own version): narrowing stays off; try it on a test instance first.",
	},
}

// ValidPreset reports whether name is a preset.
func ValidPreset(name string) bool {
	for _, p := range Presets {
		if p.Preset == name {
			return true
		}
	}
	return false
}
