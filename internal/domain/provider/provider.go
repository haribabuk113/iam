package provider

// Name is a closed enum of supported SSO providers (PRD §7). Values must
// match Supabase's own provider slugs exactly (Dashboard -> Auth ->
// Providers) — some differ from the common name: Microsoft is "azure",
// Meta is "facebook", X is "twitter". Verify against your Supabase
// project before enabling; slugs occasionally change between Supabase
// versions (e.g. Slack has moved to "slack_oidc" in newer projects).
type Name string

const (
	Google    Name = "google"
	GitHub    Name = "github"
	GitLab    Name = "gitlab"
	Microsoft Name = "azure"
	Meta      Name = "facebook"
	X         Name = "twitter"
	Discord   Name = "discord"
	Twitch    Name = "twitch"
	Slack     Name = "slack"
	Snapchat  Name = "snapchat"
)

// Apple is intentionally absent (PRD §7) — not representable, not just disabled.

func (n Name) Valid() bool {
	switch n {
	case Google, GitHub, GitLab, Microsoft, Meta, X, Discord, Twitch, Slack, Snapchat:
		return true
	default:
		return false
	}
}
