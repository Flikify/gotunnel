// filename: gotunnel.go
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls" // <-- We only need the standard library TLS
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// ========= 证书管理相关常量 =========
const (
	certDir          = "certs"
	caCertFile       = "ca.crt"
	caKeyFile        = "ca.key"
	serverCertFile   = "server.crt"
	serverKeyFile    = "server.key"
	internalCertName = "gotunnel.internal" // 用于证书的内部固定主机名
)

// ControlMessage 和 ControlResponse 结构体
type ControlMessage struct {
	RemotePort int `json:"remote_port"`
}
type ControlResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ConnectionPool
type ConnectionPool struct {
	conns      chan net.Conn
	targetAddr string
	maxSize    int
}

func NewConnectionPool(target string, size int) (*ConnectionPool, error) {
	if size <= 0 {
		return nil, fmt.Errorf("连接池大小必须为正数")
	}
	return &ConnectionPool{
		conns:      make(chan net.Conn, size),
		targetAddr: target,
		maxSize:    size,
	}, nil
}
func (p *ConnectionPool) Get() (net.Conn, error) {
	select {
	case conn := <-p.conns:
		return conn, nil
	default:
		return net.Dial("tcp", p.targetAddr)
	}
}
func (p *ConnectionPool) Put(conn net.Conn) {
	select {
	case p.conns <- conn:
	default:
		_ = conn.Close()
	}
}
func (p *ConnectionPool) Close() {
	close(p.conns)
	for conn := range p.conns {
		_ = conn.Close()
	}
}

// handleStream
func handleStream(p1, p2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(p2, p1)
		p2.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(p1, p2)
		p1.Close()
	}()
	wg.Wait()
}


// ======================= PSK 认证逻辑 =======================
const pskAuthTimeout = 5 * time.Second

func authenticateClient(conn net.Conn, expectedSecret string) error {
	_ = conn.SetReadDeadline(time.Now().Add(pskAuthTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	reader := bufio.NewReader(conn)
	receivedSecret, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("读取 secret 失败: %w", err)
	}
	if strings.TrimSpace(receivedSecret) != expectedSecret {
		_, _ = conn.Write([]byte("ERROR: Invalid Secret\n"))
		return fmt.Errorf("无效的 secret")
	}
	_, err = conn.Write([]byte("OK\n"))
	return err
}

func authenticateWithServer(conn net.Conn, secret string) error {
	if _, err := fmt.Fprintln(conn, secret); err != nil {
		return fmt.Errorf("发送 secret 失败: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(pskAuthTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("读取服务端响应失败: %w", err)
	}
	if strings.TrimSpace(response) != "OK" {
		return fmt.Errorf("认证失败，服务端响应: %s", strings.TrimSpace(response))
	}
	return nil
}

// ======================= 服务端逻辑 =======================

// getSNI 从一个连接中窥探 TLS ClientHello 消息并提取 SNI 主机名。
// 它不会从连接中消耗数据，后续仍然可以读取完整的 ClientHello。
func getSNI(conn net.Conn) (string, error) {
	// 设置一个短暂的读取超时，防止恶意连接不发送数据
	err := conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		return "", fmt.Errorf("设置超时失败: %w", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var clientHello *tls.ClientHelloInfo
	reader := bufio.NewReader(conn)

	peekedBytes, err := reader.Peek(1)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			return "", nil
		}
		if err == io.EOF {
			return "", nil
		}
		return "", fmt.Errorf("无法窥探连接: %w", err)
	}

	if peekedBytes[0] != 0x16 {
		log.Printf("来自 %s 的连接不是 TLS 握手 (第一个字节: 0x%x)，将作为普通 TCP 处理", conn.RemoteAddr(), peekedBytes[0])
		return "", nil // 不是 TLS 握手，可能是普通的 HTTP 或其他协议
	}

	err = tls.Server(struct{ net.Conn }{reader}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello = hello
			return nil, fmt.Errorf("中断以获取 SNI")
		},
	}).Handshake()

	if err != nil && !strings.Contains(err.Error(), "中断以获取 SNI") {
		log.Printf("解析 ClientHello 失败: %v。可能不是有效的 TLS 流量。", err)
		return "", nil
	}

	if clientHello != nil {
		log.Printf("从公网连接 %s 提取到 SNI: %s", conn.RemoteAddr(), clientHello.ServerName)
		return clientHello.ServerName, nil
	}

	return "", nil // 没有 SNI
}


func runServer(listenAddr, secret string) {
	log.Printf("服务端模式：隧道监听于 %s", listenAddr)

	tlsConfig, caCert, err := setupServerTLS()
	if err != nil {
		log.Fatalf("初始化 TLS 配置失败: %v", err)
	}

	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		log.Fatalf("无法监听 TLS 地址 %s: %v", listenAddr, err)
	}
	defer listener.Close()

	fmt.Println("\n======================= SERVER IS RUNNING (SECURE) =======================")
	fmt.Printf("共享密钥 (Secret): %s\n", secret)
	fmt.Printf("监听地址 (Listening on): %s\n", listener.Addr().String())
	fmt.Println("\n请在客户端机器上创建一个 ca.crt 文件, 并将以下内容复制进去:")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	fmt.Print(string(pemData))
	fmt.Println("\n然后使用类似如下命令连接 (请将 <server_ip> 和 <listen_port> 替换为实际值):")
	fmt.Printf("./gotunnel client -server <server_ip>:%s -secret \"%s\" -ca ./ca.crt -remote-port 8080 -local-target 127.0.0.1:80\n", strings.TrimPrefix(listenAddr, ":"), secret)
	fmt.Println("==========================================================================")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受 TLS 连接失败: %v", err)
			continue
		}

		go func(tlsConn net.Conn) {
			log.Printf("新 TLS 连接来自 %s，正在进行应用层 PSK 认证...", tlsConn.RemoteAddr())
			if err := authenticateClient(tlsConn, secret); err != nil {
				log.Printf("来自 %s 的认证失败: %v", tlsConn.RemoteAddr(), err)
				tlsConn.Close()
				return
			}
			log.Printf("客户端 %s 已通过 PSK 认证", tlsConn.RemoteAddr())
			handleClientSession(tlsConn)
		}(conn)
	}
}

func handleClientSession(tunnelConn net.Conn) {
	defer tunnelConn.Close()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	session, err := smux.Server(tunnelConn, smuxConfig)
	if err != nil {
		log.Printf("客户端 %s 无法创建 smux 服务端会话: %v", tunnelConn.RemoteAddr(), err)
		return
	}
	defer session.Close()

	log.Printf("[%s] 等待客户端发送控制指令...", tunnelConn.RemoteAddr())
	controlStream, err := session.AcceptStream()
	if err != nil {
		log.Printf("[%s] 接受控制流失败: %v", tunnelConn.RemoteAddr(), err)
		return
	}

	var ctrlMsg ControlMessage
	if err := json.NewDecoder(controlStream).Decode(&ctrlMsg); err != nil {
		log.Printf("[%s] 解析控制消息失败: %v", tunnelConn.RemoteAddr(), err)
		_ = json.NewEncoder(controlStream).Encode(ControlResponse{Status: "error", Message: "Invalid control message"})
		controlStream.Close(); return
	}
	log.Printf("[%s] 收到控制指令：请求转发公网端口 :%d", tunnelConn.RemoteAddr(), ctrlMsg.RemotePort)
	publicListenAddr := fmt.Sprintf(":%d", ctrlMsg.RemotePort)
	publicListener, err := net.Listen("tcp", publicListenAddr)
	if err != nil {
		errMsg := fmt.Sprintf("监听公网端口 %s 失败: %v", publicListenAddr, err); log.Printf("[%s] %s", tunnelConn.RemoteAddr(), errMsg)
		_ = json.NewEncoder(controlStream).Encode(ControlResponse{Status: "error", Message: errMsg}); controlStream.Close(); return
	}
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if session.IsClosed() {
				log.Printf("[%s] 检测到 smux 会话已关闭，正在关闭公网监听器 %s", tunnelConn.RemoteAddr(), publicListener.Addr())
				publicListener.Close(); return
			}
		}
	}()
	successMsg := fmt.Sprintf("成功在 %s 上监听, 准备转发流量", publicListener.Addr().String()); log.Printf("[%s] %s", tunnelConn.RemoteAddr(), successMsg)
	err = json.NewEncoder(controlStream).Encode(ControlResponse{Status: "success", Message: successMsg}); controlStream.Close()
	if err != nil {
		log.Printf("[%s] 发送成功响应失败: %v", tunnelConn.RemoteAddr(), err)
		publicListener.Close(); return
	}

	log.Printf("[%s] 开始为 %s 接受公网连接...", tunnelConn.RemoteAddr(), publicListener.Addr())
	for {
		userConn, err := publicListener.Accept()
		if err != nil {
			log.Printf("[%s] 公网监听器已关闭或遇到错误，停止接受新连接。原因: %v", tunnelConn.RemoteAddr(), err)
			return
		}
		if session.IsClosed() {
			log.Printf("[%s] 会话已关闭，拒绝新的公网连接 %s", tunnelConn.RemoteAddr(), userConn.RemoteAddr())
			userConn.Close(); continue
		}

		go func(publicConn net.Conn) {
			defer publicConn.Close()
			sni, _ := getSNI(publicConn)
			dataStream, err := session.OpenStream()
			if err != nil {
				log.Printf("[%s] 无法在 smux 会话上打开新流: %v", tunnelConn.RemoteAddr(), err)
				return
			}
			defer dataStream.Close()

			if _, err := fmt.Fprintf(dataStream, "%s\n", sni); err != nil {
				log.Printf("[%s] 无法发送 SNI 元数据到客户端: %v", tunnelConn.RemoteAddr(), err)
				return
			}
			log.Printf("[%s] 元数据(SNI: '%s')发送完毕，开始双向转发 %s 的流量", tunnelConn.RemoteAddr(), sni, publicConn.RemoteAddr())
			handleStream(publicConn, dataStream)
			log.Printf("[%s] 公网连接 %s 的会话已结束", tunnelConn.RemoteAddr(), publicConn.RemoteAddr())

		}(userConn)
	}
}


// ======================= 客户端逻辑 =======================

func runClient(serverAddr, secret, localTargetAddr, caCertPath string, remotePort int, maxRetryInterval time.Duration) {
	log.Printf("客户端模式启动：目标服务端 %s (安全)", serverAddr)
	log.Printf("-> 远程端口 :%d -> 本地目标 %s", remotePort, localTargetAddr)

	tlsConfig, err := setupClientTLS(caCertPath)
	if err != nil {
		log.Fatalf("初始化客户端 TLS 配置失败: %v", err)
	}

	var currentRetryInterval = 2 * time.Second
	for {
		var tunnelConn net.Conn
		for {
			log.Printf("正在尝试建立到服务端 %s 的 TLS 连接...", serverAddr)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			dialer := &tls.Dialer{Config: tlsConfig}
			conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
			cancel()

			if err != nil {
				log.Printf("TLS 连接失败: %v", err)
			} else {
				log.Println("TLS 连接成功，正在进行应用层 PSK 认证...")
				if err := authenticateWithServer(conn, secret); err != nil {
					log.Printf("认证失败: %v", err)
					_ = conn.Close()
				} else {
					log.Println("PSK 认证成功！隧道已建立。")
					tunnelConn = conn
					currentRetryInterval = 2 * time.Second
					break
				}
			}

			log.Printf("将在 %.0f 秒后重试...", currentRetryInterval.Seconds())
			time.Sleep(currentRetryInterval)
			currentRetryInterval *= 2
			jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
			currentRetryInterval += jitter
			if currentRetryInterval > maxRetryInterval {
				currentRetryInterval = maxRetryInterval
			}
		}

		runClientSession(tunnelConn, localTargetAddr, remotePort)

		log.Println("与服务端的连接已断开，准备自动重连...")
		time.Sleep(2 * time.Second)
	}
}

type streamWrapper struct {
	reader io.Reader
	writer io.Writer
	closer io.Closer
}
func (sw *streamWrapper) Read(p []byte) (n int, err error) { return sw.reader.Read(p) }
func (sw *streamWrapper) Write(p []byte) (n int, err error){ return sw.writer.Write(p) }
func (sw *streamWrapper) Close() error { return sw.closer.Close() }


func runClientSession(tunnelConn net.Conn, localTargetAddr string, remotePort int) {
	defer tunnelConn.Close()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	session, err := smux.Client(tunnelConn, smuxConfig)
	if err != nil {
		log.Printf("创建 smux 客户端会话失败: %v", err)
		return
	}
	defer session.Close()

	localConnPool, err := NewConnectionPool(localTargetAddr, 10)
	if err != nil {
		log.Printf("创建本地连接池失败: %v", err)
		return
	}
	defer localConnPool.Close()

	if err := requestPortForwarding(session, remotePort); err != nil {
		log.Printf("请求端口转发失败: %v", err)
		return
	}

	var wg sync.WaitGroup

	log.Println("控制指令发送成功，开始监听并转发流量...")
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "broken pipe") {
				log.Println("隧道会话已关闭。")
			} else {
				log.Printf("无法接受新流: %v", err)
			}
			break
		}
		
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer stream.Close()
			
			log.Println("收到新的转发请求，正在读取元数据...")
			
			streamReader := bufio.NewReader(stream)
			sni, err := streamReader.ReadString('\n')
			if err != nil {
				log.Printf("读取 SNI 元数据失败: %v", err)
				return
			}
			sni = strings.TrimSpace(sni)

			var localConn net.Conn
			if sni != "" {
				log.Printf("检测到 SNI '%s'，正在建立到 %s 的 TLS 连接", sni, localTargetAddr)
				tlsConfig := &tls.Config{
					ServerName:         sni,
					InsecureSkipVerify: true,
				}
				localConn, err = tls.Dial("tcp", localTargetAddr, tlsConfig)
			} else {
				log.Printf("未检测到 SNI，正在建立到 %s 的普通 TCP 连接", localTargetAddr)
				localConn, err = localConnPool.Get()
			}
			
			if err != nil {
				log.Printf("无法建立到本地目标的连接 %s: %v", localTargetAddr, err)
				return
			}
			defer localConn.Close()

			wrappedStream := &streamWrapper{
				reader: streamReader,
				writer: stream,
				closer: stream,
			}
			handleStream(localConn, wrappedStream)
		}()
	}

	log.Println("等待所有正在处理的流完成...")
	wg.Wait()
	log.Println("所有流已处理完毕，正在关闭会话。")
}


func requestPortForwarding(session *smux.Session, port int) error {
	log.Println("正在打开控制流以发送端口转发请求...")
	controlStream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("无法打开 smux 控制流: %w", err)
	}
	defer controlStream.Close()

	req := ControlMessage{RemotePort: port}
	if err := json.NewEncoder(controlStream).Encode(req); err != nil {
		return fmt.Errorf("发送控制消息失败: %w", err)
	}

	var resp ControlResponse
	_ = controlStream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewDecoder(controlStream).Decode(&resp); err != nil {
		return fmt.Errorf("读取服务端响应失败: %w", err)
	}

	if resp.Status != "success" {
		return fmt.Errorf("服务端返回错误: %s", resp.Message)
	}

	log.Printf("服务端成功响应: %s", resp.Message)
	return nil
}


// ======================= TLS 和 证书管理 (无修改) =======================
func setupClientTLS(caCertPath string) (*tls.Config, error) {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("无法读取 CA 证书文件 %s: %w", caCertPath, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("无法将 CA 证书添加到池中")
	}

	return &tls.Config{
		RootCAs:    caCertPool,
		ServerName: internalCertName,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func setupServerTLS() (*tls.Config, *x509.Certificate, error) {
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		if err := os.Mkdir(certDir, 0700); err != nil {
			return nil, nil, fmt.Errorf("无法创建证书目录: %w", err)
		}
	}

	caCertPath := filepath.Join(certDir, caCertFile)
	serverCertPath := filepath.Join(certDir, serverCertFile)

	var caCert *x509.Certificate
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		log.Println("未找到 CA 证书，将生成新的 CA 和服务器证书...")
		var errGen error
		caCert, errGen = generateAndSaveCerts(internalCertName)
		if errGen != nil {
			return nil, nil, fmt.Errorf("生成证书失败: %w", errGen)
		}
		log.Println("新证书生成成功！")
	} else {
		log.Println("发现现有证书，将加载它们。")
		caCertBytes, errRead := os.ReadFile(caCertPath)
		if errRead != nil {
			return nil, nil, fmt.Errorf("读取 CA 证书失败: %w", errRead)
		}
		caBlock, _ := pem.Decode(caCertBytes)
		if caBlock == nil {
			return nil, nil, fmt.Errorf("无法解码 CA 证书 PEM: %s", caCertPath)
		}
		caCert, errRead = x509.ParseCertificate(caBlock.Bytes)
		if errRead != nil {
			return nil, nil, fmt.Errorf("解析 CA 证书失败: %w", errRead)
		}
	}

	serverCert, err := tls.LoadX509KeyPair(serverCertPath, filepath.Join(certDir, serverKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("无法加载服务器证书/密钥对: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}, caCert, nil
}


func generateAndSaveCerts(hostNameForCert string) (*x509.Certificate, error) {
	caKey, caCert, err := createCertificate(nil, nil, true, "GoTunnel CA", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("创建 CA 失败: %w", err)
	}
	if err := savePEM(filepath.Join(certDir, caCertFile), filepath.Join(certDir, caKeyFile), caCert, caKey); err != nil {
		return nil, err
	}
	var ips []net.IP
	var dnsNames []string
	if ip := net.ParseIP(hostNameForCert); ip != nil {
		ips = append(ips, ip)
	} else {
		dnsNames = append(dnsNames, hostNameForCert)
	}
	serverKey, serverCert, err := createCertificate(caCert, caKey, false, hostNameForCert, ips, dnsNames)
	if err != nil {
		return nil, fmt.Errorf("创建服务器证书失败: %w", err)
	}
	if err := savePEM(filepath.Join(certDir, serverCertFile), filepath.Join(certDir, serverKeyFile), serverCert, serverKey); err != nil {
		return nil, err
	}
	return caCert, nil
}

func createCertificate(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, commonName string, ips []net.IP, dnsNames []string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil { return nil, nil, err }
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cryptorand.Int(cryptorand.Reader, serialNumberLimit)
	if err != nil { return nil, nil, err }
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     dnsNames,
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}
	var ca, signingKey = &template, privateKey
	if parent != nil && parentKey != nil {
		ca, signingKey = parent, parentKey
	}
	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &template, ca, &privateKey.PublicKey, signingKey)
	if err != nil { return nil, nil, err }
	cert, err := x509.ParseCertificate(derBytes)
	return privateKey, cert, err
}

func savePEM(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certOut, err := os.Create(certPath)
	if err != nil { return err }
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil { return err }
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil { return err }
	defer keyOut.Close()
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil { return err }
	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}


// ======================= 主函数 (无修改)  =======================
func main() {
	_, _ = rand.Read(make([]byte, 1))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		fmt.Println("错误: 必须提供一个运行模式作为子命令 ('server' 或 'client')")
		fmt.Println("\n使用 'gotunnel server -h' 查看服务端帮助")
		fmt.Println("使用 'gotunnel client -h' 查看客户端帮助")
		os.Exit(1)
	}

	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	sSecret := serverFlags.String("secret", "", "共享密钥 (必需)")
	sListenPort := serverFlags.String("listen", "7000", "用于监听客户端隧道的端口")

	clientFlags := flag.NewFlagSet("client", flag.ExitOnError)
	cSecret := clientFlags.String("secret", "", "共享密钥 (必需)")
	cServerAddr := clientFlags.String("server", "", "服务端的地址, 例如: my.server.com:7000 (必需)")
	cCaCertPath := clientFlags.String("ca", "ca.crt", "CA 证书文件路径")
	cLocalTarget := clientFlags.String("local-target", "127.0.0.1:80", "要转发流量的本地目标地址")
	cRemotePort := clientFlags.Int("remote-port", 8080, "希望在服务端暴露的公网端口")
	cMaxRetry := clientFlags.Duration("max-retry-interval", 60*time.Second, "自动重连的最大等待间隔")


	switch os.Args[1] {
	case "server":
		serverFlags.Parse(os.Args[2:])
		if *sSecret == "" {
			log.Println("错误: [Server模式] 必须提供 -secret 参数")
			serverFlags.PrintDefaults()
			os.Exit(1)
		}
		listenAddr := ":" + *sListenPort
		runServer(listenAddr, *sSecret)

	case "client":
		clientFlags.Parse(os.Args[2:])
		if *cSecret == "" || *cServerAddr == "" {
			log.Println("错误: [Client模式] 必须提供 -secret 和 -server 参数")
			clientFlags.PrintDefaults()
			os.Exit(1)
		}
		runClient(*cServerAddr, *cSecret, *cLocalTarget, *cCaCertPath, *cRemotePort, *cMaxRetry)

	default:
		fmt.Printf("错误: 无效的子命令 '%s'，必须是 'server' 或 'client'\n", os.Args[1])
		fmt.Println("\n使用 'gotunnel server -h' 查看服务端帮助")
		fmt.Println("使用 'gotunnel client -h' 查看客户端帮助")
		os.Exit(1)
	}
}
