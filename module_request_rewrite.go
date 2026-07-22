package main

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

const maxModuleRequestRewriteURLBytes = 16 << 10

func authorizeModuleRequestURLRewrite(module Module, currentURL, rawTargetURL string) (*url.URL, error) {
	return authorizeModuleRequestURLRewriteConfig(Config{}, module, currentURL, rawTargetURL)
}

func authorizeModuleRequestURLRewriteConfig(cfg Config, module Module, currentURL, rawTargetURL string) (*url.URL, error) {
	if len(rawTargetURL) == 0 || len(rawTargetURL) > maxModuleRequestRewriteURLBytes {
		return nil, fmt.Errorf("request URL rewrite must contain 1 to %d bytes", maxModuleRequestRewriteURLBytes)
	}
	rawTarget, err := url.Parse(rawTargetURL)
	if err != nil || (rawTarget.Scheme != "http" && rawTarget.Scheme != "https") {
		return nil, errors.New("request URL rewrite must be an absolute HTTP URL")
	}
	current, currentOrigin, _, err := parseModuleNetworkRequestURL(currentURL)
	if err != nil {
		return nil, fmt.Errorf("current request URL is invalid: %w", err)
	}
	target, targetOrigin, _, err := parseModuleNetworkRequestURL(rawTargetURL)
	if err != nil {
		return nil, fmt.Errorf("request URL rewrite is invalid: %w", err)
	}

	if targetOrigin == currentOrigin {
		ownsHost := moduleOwnsHost(module, target.Hostname())
		if cfg.runtime != nil && cfg.runtime.moduleHosts[module.ID] != nil {
			ownsHost = cfg.runtime.moduleHosts[module.ID].Match(target.Hostname())
		}
		if !ownsHost && !moduleDeclaresNetworkOrigin(module, targetOrigin) {
			return nil, errors.New("same-origin rewrite target is outside the extension boundary")
		}
		// Same-origin rewrites retain the existing URL representation behavior.
		// The strict parser above still rejects credentials, fragments, opaque
		// URLs, and non-HTTP schemes.
		return rawTarget, nil
	}

	if current.Scheme == "https" && target.Scheme != "https" {
		return nil, errors.New("request URL rewrite cannot downgrade HTTPS to HTTP")
	}
	if rawTarget.Scheme+"://"+rawTarget.Host != targetOrigin {
		return nil, errors.New("cross-origin request URL origin must be canonical")
	}
	if !moduleDeclaresNetworkOrigin(module, targetOrigin) {
		return nil, fmt.Errorf("cross-origin request URL origin %q is not declared", targetOrigin)
	}
	return target, nil
}

func moduleDeclaresNetworkOrigin(module Module, origin string) bool {
	for _, allowed := range module.NetworkOrigins {
		if allowed == origin {
			return true
		}
	}
	return false
}

func authorizeModuleRequestActionURL(cfg Config, module Module, rawURL string) error {
	parsed, origin, _, err := parseModuleNetworkRequestURL(rawURL)
	if err != nil {
		return fmt.Errorf("current request URL is invalid: %w", err)
	}
	ownsHost := moduleOwnsHost(module, parsed.Hostname())
	if cfg.runtime != nil && cfg.runtime.moduleHosts[module.ID] != nil {
		ownsHost = cfg.runtime.moduleHosts[module.ID].Match(parsed.Hostname())
	}
	if ownsHost || moduleDeclaresNetworkOrigin(module, origin) {
		return nil
	}
	return fmt.Errorf("current request origin %q is outside this extension's capture hosts and declared network origins", origin)
}

func activeModuleUpstreamTarget(cfg Config, rawHost, portText string) (socksTarget, bool) {
	if !cfg.MITM.Enabled {
		return socksTarget{}, false
	}
	host := canonicalHost(rawHost)
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return socksTarget{}, false
	}
	if (port == 80 || port == 443) && activeInterceptHost(cfg, host) {
		return socksTarget{Host: mappedInterceptTarget(cfg, host), Port: port}, true
	}
	for _, module := range cfg.Modules {
		if !module.Enabled {
			continue
		}
		for _, origin := range module.NetworkOrigins {
			_, canonical, target, parseErr := parseModuleNetworkRequestURL(origin)
			if parseErr == nil && canonical == origin && target.Host == host && target.Port == port {
				return target, true
			}
		}
	}
	return socksTarget{}, false
}
