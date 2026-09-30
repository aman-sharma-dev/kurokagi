package engine

import (
	"context"
	"net/http"
	"sort"

	"github.com/kurokagi/kurokagi/internal/config"
)

// CredentialProvider applies one identity's credentials to an outbound
// request. Implementations must never expose credential values in errors.
type CredentialProvider interface {
	// Apply adds the credential to request, respecting ctx cancellation.
	Apply(context.Context, *http.Request) error
}

type headerCredential struct{ name, value string }

func (p headerCredential) Apply(ctx context.Context, request *http.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	request.Header.Set(p.name, p.value)
	return nil
}

type bearerCredential struct{ token string }

func (p bearerCredential) Apply(ctx context.Context, request *http.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	return nil
}

type cookieCredential struct{ name, value string }

func (p cookieCredential) Apply(ctx context.Context, request *http.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	request.AddCookie(&http.Cookie{Name: p.name, Value: p.value})
	return nil
}

func credentialProviders(identity config.Identity) []CredentialProvider {
	providers := make([]CredentialProvider, 0, len(identity.Headers)+len(identity.Credentials))
	headerNames := make([]string, 0, len(identity.Headers))
	for name := range identity.Headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	for _, name := range headerNames {
		providers = append(providers, headerCredential{name: name, value: identity.Headers[name]})
	}
	for _, credential := range identity.Credentials {
		switch credential.Type {
		case "header":
			providers = append(providers, headerCredential{name: credential.Name, value: credential.Value})
		case "bearer":
			providers = append(providers, bearerCredential{token: credential.Value})
		case "cookie":
			providers = append(providers, cookieCredential{name: credential.Name, value: credential.Value})
		}
	}
	return providers
}
