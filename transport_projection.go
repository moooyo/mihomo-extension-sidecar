package main

import (
	"net/netip"
	"strconv"
)

// upstreamTransportProjection contains only the immutable state needed by one
// generation of pooled upstream transports. In particular, it must not retain
// the compiled script runtime or decoded script settings from Config.
type upstreamTransportProjection struct {
	generation uint64
	proxy      ProxyConfig
	http2      bool
	targets    upstreamTargetProjection
}

type upstreamTargetProjection struct {
	enabled     bool
	activeHosts *compiledHostMatcher
	modules     []upstreamModuleProjection
	// networkGrant is true when any enabled module holds the network
	// permission. That grant carries no origin list, so there is nothing to
	// enumerate: it either makes every target servable or none.
	networkGrant bool
}

type upstreamModuleProjection struct {
	hosts    *compiledHostMatcher
	mappings []HostMapping
}

// inboundUDPAuthorization is captured when a SOCKS UDP association starts.
// The snapshot preserves association authorization without retaining scripts.
type inboundUDPAuthorization struct {
	enabled     bool
	activeHosts *compiledHostMatcher
}

func newUpstreamTransportProjection(cfg Config) upstreamTransportProjection {
	targets := upstreamTargetProjection{
		enabled:      cfg.MITM.Enabled,
		activeHosts:  projectedActiveHostMatcher(cfg),
		networkGrant: false,
	}
	for _, module := range cfg.Modules {
		if !module.Enabled {
			continue
		}
		projectedModule := upstreamModuleProjection{
			hosts:    projectedModuleHostMatcher(cfg, module),
			mappings: make([]HostMapping, 0, len(module.HostMappings)),
		}
		for _, mapping := range module.HostMappings {
			projectedModule.mappings = append(projectedModule.mappings, HostMapping{
				Pattern: mapping.Pattern,
				Target:  mapping.Target,
			})
		}
		targets.modules = append(targets.modules, projectedModule)
		if module.Network {
			targets.networkGrant = true
		}
	}
	return upstreamTransportProjection{
		generation: cfg.generation,
		proxy:      cfg.UpstreamProxy,
		http2:      cfg.MITM.HTTP2,
		targets:    targets,
	}
}

func newInboundUDPAuthorization(cfg Config) inboundUDPAuthorization {
	return inboundUDPAuthorization{
		enabled:     cfg.MITM.Enabled,
		activeHosts: projectedActiveHostMatcher(cfg),
	}
}

func projectedActiveHostMatcher(cfg Config) *compiledHostMatcher {
	// Matchers are separately allocated immutable values with no back-reference
	// to compiledScriptConfig, so sharing one does not retain script state.
	if cfg.runtime != nil && cfg.runtime.activeHosts != nil {
		return cfg.runtime.activeHosts
	}
	return newCompiledHostMatcher(activeHostPatterns(cfg))
}

func projectedModuleHostMatcher(cfg Config, module Module) *compiledHostMatcher {
	// Reuse the immutable matcher allocation without retaining its parent map.
	if cfg.runtime != nil {
		if matcher := cfg.runtime.moduleHosts[module.ID]; matcher != nil {
			return matcher
		}
	}
	return newCompiledHostMatcher(module.CaptureHosts)
}

func (p upstreamTargetProjection) upstreamTarget(rawHost, portText string) (socksTarget, bool) {
	if !p.enabled {
		return socksTarget{}, false
	}
	host := canonicalHost(rawHost)
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return socksTarget{}, false
	}
	if (port == 80 || port == 443) && p.activeHosts.Match(host) {
		bestPattern := ""
		target := host
		for _, module := range p.modules {
			if !module.hosts.Match(host) {
				continue
			}
			for _, mapping := range module.mappings {
				if !matchHostPattern(mapping.Pattern, host) {
					continue
				}
				if mapping.Pattern == host || len(mapping.Pattern) > len(bestPattern) {
					bestPattern = mapping.Pattern
					target = mapping.Target
				}
			}
		}
		return socksTarget{Host: target, Port: port}, true
	}
	if !p.networkGrant {
		return socksTarget{}, false
	}
	return socksTarget{Host: host, Port: port}, true
}

func (a inboundUDPAuthorization) allows(target socksTarget) bool {
	if !a.enabled || target.Port != 443 {
		return false
	}
	if a.activeHosts.Match(target.Host) {
		return true
	}
	ip, err := netip.ParseAddr(target.Host)
	return err == nil && ip.Zone() == ""
}
