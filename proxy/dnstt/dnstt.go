// Package dnstt implements a DNSTT (SlowDNS) outbound for Xray.
//
// It is a dialerProxy: another outbound (e.g. VMess/VLESS) points its
// streamSettings.sockopt.dialerProxy at this outbound's tag, and the
// core routes that outbound's server dial through this handler's
// Process. The handler opens a stream on ONE shared DNSTT session
// (transport/internet/dnstt: resolver UDP -> KCP -> Noise_NK ->
// smux, inner "fixed") and pipes the connection through it.
//
// The session's streams go to the server's fixed port, which must be
// the inbound port of the server the calling outbound dials — the
// handler never sees the destination address (inner "fixed" ignores
// it), it only carries the bytes. There is no SOCKS listener and no
// separate process: the tunnel runs in-process, inside the core.
//
// Limitations (by protocol design, not by implementation):
//   - TCP only. DNSTT carries TCP streams; UDP destinations are
//     rejected. (DNS itself is served by Xray's own DNS outbound,
//     not by this handler.)
package dnstt

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/dnstt"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c, err := NewClient(ctx, config.(*Config))
		if err != nil {
			return nil, err
		}
		return c, nil
	}))
}

// Client is a DNSTT outbound handler: one shared DNSTT session,
// one stream per connection.
type Client struct {
	config        *Config
	policyManager policy.Manager

	dnsttDial *dnstt.Dialer
}

// NewClient creates a DNSTT outbound handler from its config. It
// validates the settings but does not dial anything yet: the DNSTT
// session is established lazily on the first Process call.
func NewClient(ctx context.Context, config *Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("dnstt: nil config")
	}
	dialer, err := dnstt.NewDialerWithRecordType(config.Ns, config.Pubkey, config.Resolver, int(config.KcpWindow), config.RecordType)
	if err != nil {
		return nil, errors.New("dnstt: invalid settings").Base(err)
	}
	c := &Client{config: config, dnsttDial: dialer}
	if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
		c.policyManager = pm
		return nil
	}); err != nil {
		return nil, err
	}
	return c, nil
}

// Close releases the shared DNSTT session and its UDP socket.
func (c *Client) Close() error {
	if c.dnsttDial != nil {
		return c.dnsttDial.Close()
	}
	return nil
}

// Process implements proxy.Outbound.Process. The target is the
// calling outbound's server address; it is ignored for routing
// (inner "fixed" forwards every stream to the server's fixed port)
// but is used in the error message when the stream cannot be opened.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("dnstt: target not specified.")
	}
	ob.Name = "dnstt"
	ob.CanSpliceCopy = 2
	destination := ob.Target

	if destination.Network == net.Network_UDP {
		// DNSTT carries TCP streams only; there is no UDP channel.
		return errors.New("dnstt: UDP is not supported by the DNSTT outbound")
	}

	// The DNSTT session ignores the address (inner "fixed"); the
	// stream goes to the server's fixed port, which must be the
	// inbound port of the server the caller dials.
	stream, err := c.dnsttDial.DialContext(ctx, "tcp", destination.NetAddr())
	if err != nil {
		return errors.New("dnstt: open stream to ", destination).Base(err)
	}
	defer stream.Close()

	p := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
	}, p.Timeouts.ConnectionIdle)

	requestFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(stream), buf.UpdateActivity(timer))
	}

	responseFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(stream), link.Writer, buf.UpdateActivity(timer))
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		return errors.New("dnstt: connection ends").Base(err)
	}
	return nil
}
