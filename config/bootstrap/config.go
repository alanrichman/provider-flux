package bootstrap

import "github.com/crossplane/upjet/pkg/config"

// Configure configures individual resources by adding custom ResourceConfigurators.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("flux_bootstrap_git", func(r *config.Resource) {
		// We need to override the default group that upjet generated for
		// this resource, which would be "flux"
		r.ShortGroup = "bootstrap"

		// Skip the timeouts field as it's a Terraform meta-argument
		// and not part of the actual resource schema
		r.TerraformResource.Schema["timeouts"].Computed = false
		r.TerraformResource.Schema["timeouts"].Optional = true
		delete(r.TerraformResource.Schema, "timeouts")
	})
}
