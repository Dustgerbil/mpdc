package main

import (
	"context"
	"net"
)

// System lookups share the scan budget and also have an individual bound.
type timeoutResolver struct{ hostResolver }

func (resolver timeoutResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()
	return resolver.hostResolver.LookupCNAME(ctx, host)
}

func (resolver timeoutResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()
	return resolver.hostResolver.LookupIP(ctx, network, host)
}

func (resolver timeoutResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()
	return resolver.hostResolver.LookupHost(ctx, host)
}

func (resolver timeoutResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()
	return resolver.hostResolver.LookupMX(ctx, host)
}

func (resolver timeoutResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()
	return resolver.hostResolver.LookupTXT(ctx, host)
}
