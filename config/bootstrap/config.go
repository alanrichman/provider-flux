package bootstrap

import (
	"github.com/crossplane/upjet/pkg/config"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Configure configures individual resources by adding custom ResourceConfigurators.
func Configure(p *config.Provider) {
	p.AddResourceConfigurator("flux_bootstrap_git", func(r *config.Resource) {
		// We need to override the default group that upjet generated for
		// this resource, which would be "flux"
		r.ShortGroup = "bootstrap"

		r.TerraformResource.Schema["secret_name"].Default = "flux-system"

		r.TerraformResource.Schema["timeouts"].Type = schema.TypeMap
		r.TerraformResource.Schema["timeouts"].Optional = true
	})
}
