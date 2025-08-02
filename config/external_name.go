/*
Copyright 2022 Upbound Inc.
*/

package config

import (
	"errors"

	"github.com/crossplane/upjet/pkg/config"
)

// ExternalNameConfigs contains all external name configurations for this
// provider.
var ExternalNameConfigs = map[string]config.ExternalName{
	// flux_bootstrap_git can be imported by passing the namespace where Flux is installed
	"flux_bootstrap_git": {
		SetIdentifierArgumentFn: config.NopSetIdentifierArgument,
		GetExternalNameFn: func(tfstate map[string]any) (string, error) {
			if id, ok := tfstate["namespace"].(string); ok && id != "" {
				return id, nil
			}
			return "", errors.New("cannot find namespace in tfstate")
		},
		GetIDFn:                config.ExternalNameAsID,
		DisableNameInitializer: true,
	},
}

// ExternalNameConfigurations applies all external name configs listed in the
// table ExternalNameConfigs and sets the version of those resources to v1beta1
// assuming they will be tested.
func ExternalNameConfigurations() config.ResourceOption {
	return func(r *config.Resource) {
		if e, ok := ExternalNameConfigs[r.Name]; ok {
			r.ExternalName = e
		}
	}
}

// ExternalNameConfigured returns the list of all resources whose external name
// is configured manually.
func ExternalNameConfigured() []string {
	l := make([]string, len(ExternalNameConfigs))
	i := 0
	for name := range ExternalNameConfigs {
		// $ is added to match the exact string since the format is regex.
		l[i] = name + "$"
		i++
	}
	return l
}
