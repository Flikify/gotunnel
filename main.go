package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

const (
	certDir        = "certs"
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"
	clientCertFile = "client.crt"
	clientKeyFile  = "client.key"
)

// ClientConfig 结构用于打包客户端所需的所有配置
type ClientConfig struct {
	ServerAddr string `json:"server_addr"`
	CACert     string `json:"ca_cert"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
}

// handleStream 负责在两个连接之间双向拷贝数据
func handleStream(p1, p2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// 当p1(用户侧)断开时，我们应该只关闭写方向，让p2(隧道侧)的数据还能发回来
		// io.Copy会持续读直到EOF，如果p1是net.Conn，读到EOF意味着连接已关闭
		// 此时调用CloseWrite通知对端我们不会再发送数据
		_, _ = io.Copy(p2, p1)
		if conn, ok := p2.(interface{ CloseWrite() error }); ok {
			_ = conn.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(p1, p2)
		if conn, ok := p1.(interface{ CloseWrite() error }); ok {
			_ = conn.CloseWrite()
		}
	}()
	wg.Wait() // 等待两个方向的拷贝都完成
}

// generateAndLoadCertificates 负责生成（如果需要）并加载所有证书
// FIX: 接收 publicAddr 用于正确生成证书和客户端配置
func generateAndLoadCertificates(publicAddr string) (*tls.Config, string, error) {
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		if err := os.Mkdir(certDir, 0700); err != nil {
			return nil, "", fmt.Errorf("无法创建证书目录 %s: %w", certDir, err)
		}
	}

	serverCertPath := filepath.Join(certDir, serverCertFile)
	if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
		log.Println("未找到服务器证书，开始生成新的 CA、服务器和客户端证书...")
		// FIX: 将 publicAddr 传递给证书生成函数
		if err := generateAllCerts(publicAddr); err != nil {
			return nil, "", fmt.Errorf("证书生成失败: %w", err)
		}
		log.Println("证书生成成功！")
	} else {
		log.Println("发现现有证书，将加载它们。")
	}

	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, serverCertFile),
		filepath.Join(certDir, serverKeyFile),
	)
	if err != nil {
		return nil, "", fmt.Errorf("无法加载服务器证书/密钥对: %w", err)
	}

	caCertBytes, err := os.ReadFile(filepath.Join(certDir, caCertFile))
	if err != nil {
		return nil, "", fmt.Errorf("无法加载 CA 证书: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertBytes) {
		return nil, "", fmt.Errorf("无法将 CA 证书添加到池中")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	clientCertBytes, err := os.ReadFile(filepath.Join(certDir, clientCertFile))
	if err != nil {
		return nil, "", fmt.Errorf("无法读取客户端证书: %w", err)
	}
	clientKeyBytes, err := os.ReadFile(filepath.Join(certDir, clientKeyFile))
	if err != nil {
		return nil, "", fmt.Errorf("无法读取客户端私钥: %w", err)
	}

	clientCfg := ClientConfig{
		// FIX: 使用 publicAddr 作为客户端连接的目标地址
		ServerAddr: publicAddr,
		CACert:     string(caCertBytes),
		ClientCert: string(clientCertBytes),
		ClientKey:  string(clientKeyBytes),
	}
	jsonBytes, err := json.Marshal(clientCfg)
	if err != nil {
		return nil, "", fmt.Errorf("无法序列化客户端配置到 JSON: %w", err)
	}
	configString := base64.StdEncoding.EncodeToString(jsonBytes)

	return tlsConfig, configString, nil
}

// FIX:
// - 接收 publicAddr 用于生成包含正确 IP/DNS 的服务器证书
func generateAllCerts(publicAddr string) error {
	caKey, caCert, err := createCertificate(nil, nil, true, "MyProxy CA", nil, nil)
	if err != nil {
		return fmt.Errorf("创建 CA 失败: %w", err)
	}
	if err := savePEM(filepath.Join(certDir, caCertFile), filepath.Join(certDir, caKeyFile), caCert, caKey); err != nil {
		return err
	}

	// FIX: 解析 publicAddr 并传递给证书创建函数
	host, _, err := net.SplitHostPort(publicAddr)
	if err != nil {
		return fmt.Errorf("无效的公网地址格式 (应为 host:port): %s", publicAddr)
	}
	var ips []net.IP
	var dnsNames []string
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		dnsNames = append(dnsNames, host)
	}
	// 为通用性，总是添加本地地址
	ips = append(ips, net.ParseIP("127.0.0.1"))
	dnsNames = append(dnsNames, "localhost")

	serverKey, serverCert, err := createCertificate(caCert, caKey, false, "MyProxy Server", ips, dnsNames)
	if err != nil {
		return fmt.Errorf("创建服务器证书失败: %w", err)
	}
	if err := savePEM(filepath.Join(certDir, serverCertFile), filepath.Join(certDir, serverKeyFile), serverCert, serverKey); err != nil {
		return err
	}

	clientKey, clientCert, err := createCertificate(caCert, caKey, false, "MyProxy Client", nil, nil)
	if err != nil {
		return fmt.Errorf("创建客户端证书失败: %w", err)
	}
	return savePEM(filepath.Join(certDir, clientCertFile), filepath.Join(certDir, clientKeyFile), clientCert, clientKey)
}

// FIX: 接收 ips 和 dnsNames 用于设置证书的 SAN
func createCertificate(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, commonName string, ips []net.IP, dnsNames []string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privateKey.PublicKey, signingKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	return privateKey, cert, err
}

func savePEM(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("无法创建证书文件 %s: %w", certPath, err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("无法创建私钥文件 %s: %w", keyPath, err)
	}
	defer keyOut.Close()
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}

// FIX: 全新重构的 runServer，使其更健壮
func runServer(listenAddr, tunnelAddr, publicAddr string) {
	log.Printf("服务端模式：服务监听于 %s, 隧道监听于 %s, 公网地址为 %s", listenAddr, tunnelAddr, publicAddr)

	tlsConfig, clientConfigString, err := generateAndLoadCertificates(publicAddr)
	if err != nil {
		log.Fatalf("初始化安全配置失败: %v", err)
	}

	fmt.Println("\n========================= CLIENT CONFIGURATION =========================")
	fmt.Println("将以下单行配置字符串完整复制到客户端机器上运行:")
	fmt.Printf("\n./your_program -mode client -config \"%s\"\n\n", clientConfigString)
	fmt.Println("========================================================================")

	serviceListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("无法监听服务地址 %s: %v", listenAddr, err)
	}
	defer serviceListener.Close()
	log.Printf("服务已在 %s 上就绪, 等待用户连接...", listenAddr)

	tunnelListener, err := tls.Listen("tcp", tunnelAddr, tlsConfig)
	if err != nil {
		log.Fatalf("无法监听 TLS 隧道地址 %s: %v", tunnelAddr, err)
	}
	defer tunnelListener.Close()

	// FIX: 主循环现在是接受隧道连接，可以处理客户端重连
	for {
		log.Println("等待客户端连接隧道 (mTLS)...")
		tunnelConn, err := tunnelListener.Accept()
		if err != nil {
			log.Printf("接受隧道连接失败: %v", err)
			continue // 不要让整个服务挂掉
		}
		// 为每个隧道连接启动一个独立的会话处理器
		go handleTunnelSession(tunnelConn, serviceListener)
	}
}

// FIX: 新增函数，处理单个隧道会话的所有逻辑
func handleTunnelSession(tunnelConn net.Conn, serviceListener net.Listener) {
	log.Printf("客户端 %s 已通过 mTLS 验证并连接隧道", tunnelConn.RemoteAddr())
	defer tunnelConn.Close()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	session, err := smux.Server(tunnelConn, smuxConfig)
	if err != nil {
		log.Printf("客户端 %s 无法创建 smux 服务端会话: %v", tunnelConn.RemoteAddr(), err)
		return
	}
	defer session.Close()

	// 这个循环为当前隧道会话(session)处理来自serviceListener的请求
	for {
		if session.IsClosed() {
			log.Printf("客户端 %s 的会话已关闭，停止为其接受新用户连接。", tunnelConn.RemoteAddr())
			return
		}

		userConn, err := serviceListener.Accept()
		if err != nil {
			// 如果会话关闭，Accept可能会出错，这是正常退出路径
			if session.IsClosed() {
				return
			}
			log.Printf("接受用户连接失败: %v", err)
			continue
		}
		log.Printf("收到新用户连接 %s，将通过隧道 %s 转发", userConn.RemoteAddr(), tunnelConn.RemoteAddr())

		stream, err := session.OpenStream()
		if err != nil {
			log.Printf("无法在 smux 会话上(隧道 %s)打开新流: %v", tunnelConn.RemoteAddr(), err)
			userConn.Close()
			// 如果打开流失败，很可能smux会话已死，跳出循环，结束此goroutine
			return
		}

		go func() {
			defer userConn.Close()
			defer stream.Close()
			handleStream(userConn, stream)
			log.Printf("用户连接 %s (经由隧道 %s) 的会话已结束", userConn.RemoteAddr(), tunnelConn.RemoteAddr())
		}()
	}
}


// runClient 启动客户端逻辑 (基本无变化，仅修正日志和错误处理)
func runClient(configString, targetAddr string) {
	jsonBytes, err := base64.StdEncoding.DecodeString(configString)
	if err != nil {
		log.Fatalf("无效的配置字符串 (Base64解码失败): %v", err)
	}
	var cfg ClientConfig
	if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
		log.Fatalf("无效的配置字符串 (JSON解析失败): %v", err)
	}

	log.Printf("客户端模式：连接到远程隧道 %s，转发到本地目标 %s", cfg.ServerAddr, targetAddr)

	clientCert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
	if err != nil {
		log.Fatalf("无法加载客户端证书/密钥对: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(cfg.CACert)) {
		log.Fatal("无法将 CA 证书添加到池中")
	}

	serverHost, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		serverHost = cfg.ServerAddr
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   serverHost,
		MinVersion:   tls.VersionTLS13,
	}

	tunnelConn, err := tls.Dial("tcp", cfg.ServerAddr, tlsConfig)
	if err != nil {
		log.Fatalf("无法通过 mTLS 连接到远程隧道 %s: %v", cfg.ServerAddr, err)
	}
	log.Printf("已成功通过 mTLS 连接到隧道 %s", cfg.ServerAddr)
	defer tunnelConn.Close()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	session, err := smux.Client(tunnelConn, smuxConfig)
	if err != nil {
		log.Fatalf("无法创建 smux 客户端会话: %v", err)
	}
	defer session.Close()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			// 更优雅地处理连接关闭
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				log.Println("隧道会话已关闭，客户端退出。")
			} else {
				log.Printf("无法接受新流，客户端退出: %v", err)
			}
			return
		}
		log.Println("收到新的转发请求，正在连接本地服务...")
		localConn, err := net.Dial("tcp", targetAddr)
		if err != nil {
			log.Printf("无法连接到本地目标 %s: %v", targetAddr, err)
			stream.Close()
			continue
		}
		go func() {
			defer localConn.Close()
			defer stream.Close()
			handleStream(localConn, stream)
			log.Println("本地转发会话已结束")
		}()
	}
}

func main() {
	mode := flag.String("mode", "", "运行模式: 'server' 或 'client'")

	// Server 模式参数
	listenAddr := flag.String("listen", "localhost:5556", "[Server模式] 公开给用户访问的地址")
	tunnelAddr := flag.String("tunnel", ":7000", "[Server模式] 用于监听客户端隧道的地址")
	// FIX: 新增 public-addr 参数
	publicAddr := flag.String("public-addr", "", "[Server模式-必需] 服务器的公网地址和隧道端口 (例如: 47.110.46.147:7000 或 mydomain.com:7000)")

	// Client 模式参数
	configString := flag.String("config", "", "[Client模式-必需] 从服务端获取的单行配置字符串")
	targetAddr := flag.String("target", "localhost:5555", "[Client模式] 要转发流量的本地目标地址 (例如 adb 的 127.0.0.1:5037)")

	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds) // 使用微秒方便调试

	switch *mode {
	case "server":
		if *publicAddr == "" {
			log.Fatal("[Server模式] 错误: 必须提供 -public-addr 参数")
		}
		runServer(*listenAddr, *tunnelAddr, *publicAddr)
	case "client":
		if *configString == "" {
			log.Fatal("[Client模式] 错误: 必须提供 -config 参数")
		}
		runClient(*configString, *targetAddr)
	default:
		fmt.Println("错误: 必须指定模式 -mode 'server' 或 -mode 'client'")
		flag.PrintDefaults()
	}
}
