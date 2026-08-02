package main

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
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
	// fingerprint identifies everything a pooled transport depends on, and
	// deliberately excludes generation.
	//
	// A generation number advances whenever the validated document changes at
	// all, but almost nothing a commit changes reaches the upstream leg: a
	// setting, an enable toggle, a script body, a match pattern all leave the
	// proxy credentials, the protocol choice and the target authorization
	// exactly as they were. Retiring the pool on the number meant every commit
	// dropped every warm connection and every TLS session with it. Comparing
	// this instead keeps connections that are still authorized for exactly the
	// targets they were opened for.
	fingerprint [sha256.Size]byte
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
	// Written in the same walk that builds the projection, over the same source
	// fields, so a field cannot be added to one and forgotten in the other
	// without the two going obviously out of step.
	digest := sha256.New()
	writeFingerprintField(digest, cfg.UpstreamProxy.Address)
	writeFingerprintField(digest, cfg.UpstreamProxy.Username)
	writeFingerprintField(digest, cfg.UpstreamProxy.Password)
	writeFingerprintBool(digest, cfg.MITM.HTTP2)
	writeFingerprintBool(digest, cfg.MITM.Enabled)
	for _, module := range cfg.Modules {
		if !module.Enabled {
			continue
		}
		projectedModule := upstreamModuleProjection{
			hosts:    projectedModuleHostMatcher(cfg, module),
			mappings: make([]HostMapping, 0, len(module.HostMappings)),
		}
		// The module boundary is in the digest so that moving a host from one
		// module to another cannot collide with leaving it where it was.
		writeFingerprintField(digest, module.ID)
		for _, host := range module.CaptureHosts {
			writeFingerprintField(digest, host)
		}
		for _, mapping := range module.HostMappings {
			// The resolver form names nameservers for 5gpn-dns, not a
			// destination. Keeping it out of the projection is what stops it
			// reaching the dialler, and it covers the HTTP/3 path with the
			// same edit.
			if mapping.resolverForm() {
				continue
			}
			projectedModule.mappings = append(projectedModule.mappings, HostMapping{
				Pattern: mapping.Pattern,
				Target:  mapping.Target,
			})
			writeFingerprintField(digest, mapping.Pattern)
			writeFingerprintField(digest, mapping.Target)
		}
		targets.modules = append(targets.modules, projectedModule)
		if module.Network {
			targets.networkGrant = true
		}
		writeFingerprintBool(digest, module.Network)
	}
	writeFingerprintBool(digest, targets.networkGrant)

	projection := upstreamTransportProjection{
		generation: cfg.generation,
		proxy:      cfg.UpstreamProxy,
		http2:      cfg.MITM.HTTP2,
		targets:    targets,
	}
	digest.Sum(projection.fingerprint[:0])
	return projection
}

// writeFingerprintField writes a length-prefixed value, so that two different
// field splits cannot produce the same byte stream.
func writeFingerprintField(digest hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write([]byte(value))
}

func writeFingerprintBool(digest hash.Hash, value bool) {
	if value {
		_, _ = digest.Write([]byte{1})
		return
	}
	_, _ = digest.Write([]byte{0})
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
