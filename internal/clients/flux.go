/*
Copyright 2021 Upbound Inc.
*/

package clients

import (
	"context"
	"encoding/json"

	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/upjet/pkg/terraform"

	"github.com/alanrichman/provider-flux/apis/v1beta1"
)

const (
	// error messages
	errNoProviderConfig     = "no providerConfigRef provided"
	errGetProviderConfig    = "cannot get referenced ProviderConfig"
	errTrackUsage           = "cannot track ProviderConfig usage"
	errExtractCredentials   = "cannot extract credentials"
	errUnmarshalCredentials = "cannot unmarshal flux credentials as JSON"

	// credential keys for Git authentication
	keyGitURL                   = "git_url"
	keyGitBranch                = "git_branch"
	keyGitAuthorName            = "git_author_name"
	keyGitAuthorEmail           = "git_author_email"
	keyGitCommitMessageAppendix = "git_commit_message_appendix"
	keyGitGPGKeyID              = "git_gpg_key_id"
	keyGitGPGKeyRing            = "git_gpg_key_ring"
	keyGitGPGPassphrase         = "git_gpg_passphrase"

	// Git HTTP authentication
	keyGitHTTPUsername             = "git_http_username"
	keyGitHTTPPassword             = "git_http_password"
	keyGitHTTPAllowInsecure        = "git_http_allow_insecure"
	keyGitHTTPCertificateAuthority = "git_http_certificate_authority"

	// Git SSH authentication
	keyGitSSHUsername     = "git_ssh_username"
	keyGitSSHPrivateKey   = "git_ssh_private_key"
	keyGitSSHPassword     = "git_ssh_password"
	keyGitSSHHostkeyAlgos = "git_ssh_hostkey_algos"

	// credential keys for Kubernetes authentication
	keyKubeHost                  = "kube_host"
	keyKubeUsername              = "kube_username"
	keyKubePassword              = "kube_password"
	keyKubeInsecure              = "kube_insecure"
	keyKubeClientCertificate     = "kube_client_certificate"
	keyKubeClientKey             = "kube_client_key"
	keyKubeClusterCACertificate  = "kube_cluster_ca_certificate"
	keyKubeConfigPath            = "kube_config_path"
	keyKubeConfigPaths           = "kube_config_paths"
	keyKubeConfigContext         = "kube_config_context"
	keyKubeConfigContextAuthInfo = "kube_config_context_auth_info"
	keyKubeConfigContextCluster  = "kube_config_context_cluster"
	keyKubeToken                 = "kube_token"
	keyKubeProxyURL              = "kube_proxy_url"
	keyKubeExecAPIVersion        = "kube_exec_api_version"
	keyKubeExecCommand           = "kube_exec_command"
	keyKubeExecArgs              = "kube_exec_args"
	keyKubeExecEnv               = "kube_exec_env"
)

// TerraformSetupBuilder builds Terraform a terraform.SetupFn function which
// returns Terraform provider setup configuration
func TerraformSetupBuilder(version, providerSource, providerVersion string) terraform.SetupFn {
	return func(ctx context.Context, client client.Client, mg resource.Managed) (terraform.Setup, error) {
		ps := terraform.Setup{
			Version: version,
			Requirement: terraform.ProviderRequirement{
				Source:  providerSource,
				Version: providerVersion,
			},
		}

		configRef := mg.GetProviderConfigReference()
		if configRef == nil {
			return ps, errors.New(errNoProviderConfig)
		}
		pc := &v1beta1.ProviderConfig{}
		if err := client.Get(ctx, types.NamespacedName{Name: configRef.Name}, pc); err != nil {
			return ps, errors.Wrap(err, errGetProviderConfig)
		}

		t := resource.NewProviderConfigUsageTracker(client, &v1beta1.ProviderConfigUsage{})
		if err := t.Track(ctx, mg); err != nil {
			return ps, errors.Wrap(err, errTrackUsage)
		}

		data, err := resource.CommonCredentialExtractor(ctx, pc.Spec.Credentials.Source, client, pc.Spec.Credentials.CommonCredentialSelectors)
		if err != nil {
			return ps, errors.Wrap(err, errExtractCredentials)
		}
		creds := map[string]string{}
		if err := json.Unmarshal(data, &creds); err != nil {
			return ps, errors.Wrap(err, errUnmarshalCredentials)
		}

		// Set provider configuration
		ps.Configuration = map[string]any{}

		// Configure Git settings
		gitConfig := map[string]any{}
		if v, ok := creds[keyGitURL]; ok {
			gitConfig["url"] = v
		}
		if v, ok := creds[keyGitBranch]; ok {
			gitConfig["branch"] = v
		}
		if v, ok := creds[keyGitAuthorName]; ok {
			gitConfig["author_name"] = v
		}
		if v, ok := creds[keyGitAuthorEmail]; ok {
			gitConfig["author_email"] = v
		}
		if v, ok := creds[keyGitCommitMessageAppendix]; ok {
			gitConfig["commit_message_appendix"] = v
		}
		if v, ok := creds[keyGitGPGKeyID]; ok {
			gitConfig["gpg_key_id"] = v
		}
		if v, ok := creds[keyGitGPGKeyRing]; ok {
			gitConfig["gpg_key_ring"] = v
		}
		if v, ok := creds[keyGitGPGPassphrase]; ok {
			gitConfig["gpg_passphrase"] = v
		}

		// Configure Git HTTP authentication
		httpConfig := map[string]any{}
		if v, ok := creds[keyGitHTTPUsername]; ok {
			httpConfig["username"] = v
		}
		if v, ok := creds[keyGitHTTPPassword]; ok {
			httpConfig["password"] = v
		}
		if v, ok := creds[keyGitHTTPAllowInsecure]; ok {
			httpConfig["allow_insecure_http"] = v == "true"
		}
		if v, ok := creds[keyGitHTTPCertificateAuthority]; ok {
			httpConfig["certificate_authority"] = v
		}
		if len(httpConfig) > 0 {
			gitConfig["http"] = httpConfig
		}

		// Configure Git SSH authentication
		sshConfig := map[string]any{}
		if v, ok := creds[keyGitSSHUsername]; ok {
			sshConfig["username"] = v
		}
		if v, ok := creds[keyGitSSHPrivateKey]; ok {
			sshConfig["private_key"] = v
		}
		if v, ok := creds[keyGitSSHPassword]; ok {
			sshConfig["password"] = v
		}
		if v, ok := creds[keyGitSSHHostkeyAlgos]; ok {
			// Parse comma-separated list
			var algos []string
			if err := json.Unmarshal([]byte(v), &algos); err == nil {
				sshConfig["hostkey_algos"] = algos
			}
		}
		if len(sshConfig) > 0 {
			gitConfig["ssh"] = sshConfig
		}

		if len(gitConfig) > 0 {
			ps.Configuration["git"] = gitConfig
		}

		// Configure Kubernetes settings
		kubeConfig := map[string]any{}
		if v, ok := creds[keyKubeHost]; ok {
			kubeConfig["host"] = v
		}
		if v, ok := creds[keyKubeUsername]; ok {
			kubeConfig["username"] = v
		}
		if v, ok := creds[keyKubePassword]; ok {
			kubeConfig["password"] = v
		}
		if v, ok := creds[keyKubeInsecure]; ok {
			kubeConfig["insecure"] = v == "true"
		}
		if v, ok := creds[keyKubeClientCertificate]; ok {
			kubeConfig["client_certificate"] = v
		}
		if v, ok := creds[keyKubeClientKey]; ok {
			kubeConfig["client_key"] = v
		}
		if v, ok := creds[keyKubeClusterCACertificate]; ok {
			kubeConfig["cluster_ca_certificate"] = v
		}
		if v, ok := creds[keyKubeConfigPath]; ok {
			kubeConfig["config_path"] = v
		}
		if v, ok := creds[keyKubeConfigPaths]; ok {
			// Parse comma-separated list
			var paths []string
			if err := json.Unmarshal([]byte(v), &paths); err == nil {
				kubeConfig["config_paths"] = paths
			}
		}
		if v, ok := creds[keyKubeConfigContext]; ok {
			kubeConfig["config_context"] = v
		}
		if v, ok := creds[keyKubeConfigContextAuthInfo]; ok {
			kubeConfig["config_context_auth_info"] = v
		}
		if v, ok := creds[keyKubeConfigContextCluster]; ok {
			kubeConfig["config_context_cluster"] = v
		}
		if v, ok := creds[keyKubeToken]; ok {
			kubeConfig["token"] = v
		}
		if v, ok := creds[keyKubeProxyURL]; ok {
			kubeConfig["proxy_url"] = v
		}

		// Configure Kubernetes exec authentication
		execConfig := map[string]any{}
		if v, ok := creds[keyKubeExecAPIVersion]; ok {
			execConfig["api_version"] = v
		}
		if v, ok := creds[keyKubeExecCommand]; ok {
			execConfig["command"] = v
		}
		if v, ok := creds[keyKubeExecArgs]; ok {
			// Parse comma-separated list
			var args []string
			if err := json.Unmarshal([]byte(v), &args); err == nil {
				execConfig["args"] = args
			}
		}
		if v, ok := creds[keyKubeExecEnv]; ok {
			// Parse JSON map
			var env map[string]string
			if err := json.Unmarshal([]byte(v), &env); err == nil {
				execConfig["env"] = env
			}
		}
		if len(execConfig) > 0 {
			kubeConfig["exec"] = execConfig
		}

		if len(kubeConfig) > 0 {
			ps.Configuration["kubernetes"] = kubeConfig
		}

		return ps, nil
	}
}
