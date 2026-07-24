package main

import (
	"context"
	"fmt"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
	cgpdata "github.com/gmyzovsky/go-cgp-data"
)

// selectDomains resolves the list of domains this run will process.
//
// The default is every server domain (LISTDOMAINS), narrowed to an
// explicit Include list when one is configured. The two cluster
// selectors take precedence over both:
//
//   - OnlyShared processes the cluster-wide Shared domains. One
//     designated node runs this way.
//   - OnlyLocal processes this node's local domains: LISTDOMAINS minus
//     the Shared ones, leaving the main domain and any regular
//     non-Shared domains. Every cluster node runs this way.
//
// Requesting both cancels out - both are ignored. The Shared list is
// queried once per run and reused for both the OnlyShared and OnlyLocal
// paths; on a non-cluster server it comes back empty.
func selectDomains(ctx context.Context, c *cgpapi.Client, cfg *Config) ([]string, error) {
	onlyLocal := cfg.Domains.OnlyLocal && !cfg.Domains.OnlyShared
	onlyShared := cfg.Domains.OnlyShared && !cfg.Domains.OnlyLocal

	switch {
	case onlyShared:
		return listControlledDomains(ctx, c)
	case onlyLocal:
		all, err := listAllDomains(ctx, c)
		if err != nil {
			return nil, err
		}
		shared, err := listControlledDomains(ctx, c)
		if err != nil {
			return nil, err
		}
		return subtract(all, shared), nil
	case len(cfg.Domains.Include) > 0:
		return cfg.Domains.Include, nil
	default:
		return listAllDomains(ctx, c)
	}
}

// listAllDomains returns every server domain (LISTDOMAINS): all
// installed domains plus this node's main domain.
func listAllDomains(ctx context.Context, c *cgpapi.Client) ([]string, error) {
	out, err := c.ListDomains(ctx, nil)
	if err != nil {
		return nil, err
	}
	return domainNames(out.Domains), nil
}

// listControlledDomains returns the cluster's Shared domains via the
// LISTCONTROLLEDDOMAINS command. go-cgp-api has no typed wrapper for
// it, so it goes through the raw Send pipe. On a non-cluster server the
// result is empty.
func listControlledDomains(ctx context.Context, c *cgpapi.Client) ([]string, error) {
	v, err := c.Send(ctx, "LISTCONTROLLEDDOMAINS")
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	arr, ok := v.(cgpdata.Array)
	if !ok {
		return nil, fmt.Errorf("LISTCONTROLLEDDOMAINS: expected an array, got %T", v)
	}
	return domainNames(arr), nil
}

// domainNames renders a CLI domain-name array as plain strings, the
// same way the rest of the tool treats domain tokens.
func domainNames(arr cgpdata.Array) []string {
	names := make([]string, 0, len(arr))
	for _, d := range arr {
		names = append(names, fmt.Sprint(d))
	}
	return names
}

// subtract returns the elements of all that are not in remove.
func subtract(all, remove []string) []string {
	drop := make(map[string]bool, len(remove))
	for _, d := range remove {
		drop[d] = true
	}
	out := make([]string, 0, len(all))
	for _, d := range all {
		if !drop[d] {
			out = append(out, d)
		}
	}
	return out
}
