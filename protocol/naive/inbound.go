package naive

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
	sHttp "github.com/sagernet/sing/protocol/http"
)

var ConfigureHTTP3ListenerFunc func(listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, logger logger.Logger) (io.Closer, error)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           logger.ContextLogger
	listener         *listener.Listener
	network          []string
	networkIsDefault bool
	authenticator    *auth.Authenticator
	tlsConfig        tls.ServerConfig
	httpServer       *http.Server
	h3Server         io.Closer
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeNaive, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		networkIsDefault: options.Network == "",
		network:          options.Network.Build(),
		authenticator:    auth.NewAuthenticator(options.Users),
	}
	if common.Contains(inbound.network, N.NetworkUDP) {
		if options.TLS == nil || !options.TLS.Enabled {
			return nil, E.New("TLS is required for QUIC server")
		}
	}
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	return inbound, nil
}

func (n *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	var tlsConfig *tls.STDConfig
	if n.tlsConfig != nil {
		err := n.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		tlsConfig, err = n.tlsConfig.Config()
		if err != nil {
			return err
		}
	}
	if common.Contains(n.network, N.NetworkTCP) {
		tcpListener, err := n.listener.ListenTCP()
		if err != nil {
			return err
		}
		n.httpServer = &http.Server{
			Handler:   n,
			TLSConfig: tlsConfig,
			BaseContext: func(listener net.Listener) context.Context {
				return n.ctx
			},
		}
		go func() {
			var sErr error
			if tlsConfig != nil {
				sErr = n.httpServer.ServeTLS(tcpListener, "", "")
			} else {
				sErr = n.httpServer.Serve(tcpListener)
			}
			if sErr != nil && !E.IsClosedOrCanceled(sErr) {
				n.logger.Error("http server serve error: ", sErr)
			}
		}()
	}

	if common.Contains(n.network, N.NetworkUDP) {
		http3Server, err := ConfigureHTTP3ListenerFunc(n.listener, n, n.tlsConfig, n.logger)
		if err == nil {
			n.h3Server = http3Server
		} else if len(n.network) > 1 {
			n.logger.Warn(E.Cause(err, "naive http3 disabled"))
		} else {
			return err
		}
	}

	return nil
}

func (n *Inbound) Close() error {
	return common.Close(
		&n.listener,
		common.PtrOrNil(n.httpServer),
		n.h3Server,
		n.tlsConfig,
	)
}

func (n *Inbound) checkAuth(request *http.Request) (string, bool) {
	if n.authenticator == nil {
		return "", true
	}
	userName, password, authOk := sHttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	if !authOk || !n.authenticator.Verify(userName, password) {
		return "", false
	}
	return userName, true
}

func removeHopByHopHeaders(header http.Header) {
	// Strip hop-by-hop header based on RFC:
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
	// https://www.mnot.net/blog/2011/07/11/what_proxies_must_do

	header.Del("Proxy-Connection")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("TE")
	header.Del("Trailers")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")

	connections := header.Get("Connection")
	header.Del("Connection")
	if len(connections) == 0 {
		return
	}
	for _, h := range strings.Split(connections, ",") {
		header.Del(strings.TrimSpace(h))
	}
}

func handleProto(request *http.Request, response *http.Response) {
	response.Proto = request.Proto
	response.ProtoMajor = request.ProtoMajor
	response.ProtoMinor = request.ProtoMinor
}

func (n *Inbound) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	userName, authOk := n.checkAuth(request)
	if !authOk {
		writer.Header().Add("Proxy-Authenticate", "Basic")
		writer.WriteHeader(http.StatusProxyAuthRequired)
		n.badRequest(ctx, request, E.New("authorization failed"))
		return
	}
	hostPort := request.URL.Host
	if hostPort == "" {
		hostPort = request.Host
	}
	source := sHttp.SourceAddress(request)
	destination := M.ParseSocksaddr(hostPort)
	if request.Method != "CONNECT" {
		if request.ProtoMajor == 2 {
			writer.WriteHeader(http.StatusBadRequest)
			n.badRequest(ctx, request, E.New("not CONNECT request"))
			return
		} else {
			isUpgrade := strings.ToLower(request.Header.Get("Connection")) == "upgrade"
			if isUpgrade && request.ProtoMinor != 1 {
				writer.WriteHeader(http.StatusBadRequest)
				n.badRequest(ctx, request, E.New("not HTTP/1.1 request"))
				return
			}
			URL := request.URL
			if URL.Scheme == "" {
				var err error
				URL, err = url.Parse("https://" + URL.String())
				if err != nil {
					writer.WriteHeader(http.StatusBadRequest)
					n.badRequest(ctx, request, E.New("invalid request url"))
					return
				}
			}
			if destination.Port == 0 {
				switch URL.Scheme {
				case "https", "wss":
					destination.Port = 443
				default:
					destination.Port = 80
				}
			}
			hijacker, _ := writer.(http.Hijacker)
			conn, _, err := hijacker.Hijack()
			if err != nil {
				n.badRequest(ctx, request, E.New("hijack failed"))
				return
			}
			conn = &fastCloseConn{Conn: conn}
			pipe.Pipe()
			serverConn, clientConn := pipe.Pipe()
			go n.newConnection(ctx, false, clientConn, userName, source, destination)
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return serverConn, nil
				},
			}
			if isUpgrade {
				finalRequest, _ := http.NewRequest(request.Method, URL.String(), nil)
				finalRequest.Header = request.Header.Clone()
				finalRequest.Header.Del("Proxy-Authorization")
				finalRequest.Header.Del("Proxy-Connection")
				response, err := transport.RoundTrip(finalRequest)
				if err != nil {
					writer.WriteHeader(http.StatusInternalServerError)
					n.badRequest(ctx, request, E.Cause(err, "round trip upgrade request"))
					common.Close(conn, serverConn, clientConn)
					return
				}
				handleProto(request, response)
				err = response.Write(conn)
				if err != nil {
					n.badRequest(ctx, request, E.Cause(err, "write upgrade response"))
					common.Close(conn, serverConn, clientConn)
					return
				}
				err = bufio.CopyConn(ctx, conn, serverConn)
				if err != nil {
					n.badRequest(ctx, request, err)
				}
				return
			} else {
				defer common.Close(conn, serverConn, clientConn)
				finalRequest, _ := http.NewRequest(request.Method, URL.String(), request.Body)
				finalRequest.Header = request.Header.Clone()
				removeHopByHopHeaders(finalRequest.Header)
				response, err := transport.RoundTrip(finalRequest)
				request.Body.Close()
				if err != nil {
					writer.WriteHeader(http.StatusInternalServerError)
					n.badRequest(ctx, request, E.Cause(err, "round trip request"))
					return
				}
				if response.Header.Get("Transfer-Encoding") == "chunked" && request.ProtoMinor == 0 {
					writer.WriteHeader(http.StatusNotImplemented)
					n.badRequest(ctx, request, E.New("chuncked reponse on HTTP/1.0"))
					return
				}
				handleProto(request, response)
				err = response.Write(conn)
				response.Body.Close()
				if err != nil {
					n.badRequest(ctx, request, E.Cause(err, "write response"))
				}
				return
			}
		}
	}
	needPadding := request.Header.Get("Padding") != ""
	if needPadding {
		writer.Header().Set("Padding", generateNaivePaddingHeader())
	}
	writer.WriteHeader(http.StatusOK)
	flusher := writer.(http.Flusher)
	flusher.Flush()

	if hijacker, isHijacker := writer.(http.Hijacker); isHijacker {
		conn, _, err := hijacker.Hijack()
		if err != nil {
			n.badRequest(ctx, request, E.New("hijack failed"))
			return
		}
		conn = &fastCloseConn{Conn: conn}
		if needPadding {
			conn = &naiveH1Conn{Conn: conn}
		}
		n.newConnection(ctx, false, conn, userName, source, destination)
	} else {
		var conn net.Conn
		if needPadding {
			conn = &naiveH2Conn{reader: request.Body, writer: writer, flusher: flusher}
		} else {
			conn = &v2rayhttp.ServerHTTPConn{HTTP2Conn: v2rayhttp.NewHTTPConn(request.Body, writer), Flusher: flusher}
		}
		n.newConnection(ctx, true, conn, userName, source, destination)
	}
}

func (n *Inbound) closeConn(ctx context.Context, request *http.Request, writer http.ResponseWriter) {
	hijacker, isHijacker := writer.(http.Hijacker)
	if !isHijacker {
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		n.badRequest(ctx, request, E.New("hijack failed"))
		return
	}
	if tcpConn, isTCPConn := conn.(*net.TCPConn); isTCPConn {
		tcpConn.SetLinger(0)
	}
	conn.Close()
}

func (n *Inbound) newConnection(ctx context.Context, waitForClose bool, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr) {
	if userName != "" {
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection from ", source)
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", destination)
	} else {
		n.logger.InfoContext(ctx, "inbound connection from ", source)
		n.logger.InfoContext(ctx, "inbound connection to ", destination)
	}
	var metadata adapter.InboundContext
	metadata.Inbound = n.Tag()
	metadata.InboundType = n.Type()
	//nolint:staticcheck
	metadata.InboundDetour = n.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.InboundOptions = n.listener.ListenOptions().InboundOptions
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName
	if !waitForClose {
		n.router.RouteConnectionEx(ctx, conn, metadata, nil)
	} else {
		done := make(chan struct{})
		wrapper := v2rayhttp.NewHTTP2Wrapper(conn)
		n.router.RouteConnectionEx(ctx, conn, metadata, N.OnceClose(func(it error) {
			close(done)
		}))
		<-done
		wrapper.CloseWrapper()
	}
}

func (n *Inbound) badRequest(ctx context.Context, request *http.Request, err error) {
	n.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

func generateNaivePaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		// Codes that won't be Huffman coded.
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	return string(padding)
}
