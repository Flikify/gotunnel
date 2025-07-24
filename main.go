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
	"time"

	"github.com/xtaci/smux"
)

const (
	certDir      = "certs"
	caCertFile   = "ca.crt"
	caKeyFile    = "ca.key"
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

// handleStream 负责在两个连接之间双向拷贝数据 (无变化)
func handleStream(p1, p2 io.ReadWriteCloser) {
	go func() {
		_, _ = io.Copy(p2, p1)
		if conn, ok := p2.(interface{ CloseWrite() error }); ok {
			_ = conn.CloseWrite()
		}
	}()
	_, _ = io.Copy(p1, p2)
	if conn, ok := p1.(interface{ CloseWrite() error }); ok {
		_ = conn.CloseWrite()
	}
}

// generateAndLoadCertificates 负责生成（如果需要）并加载所有证书，返回一个可用的 tls.Config 和客户端配置字符串
func generateAndLoadCertificates(tunnelAddr string) (*tls.Config, string, error) {
	// 1. 检查并创建证书目录
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		if err := os.Mkdir(certDir, 0700); err != nil {
			return nil, "", fmt.Errorf("无法创建证书目录 %s: %w", certDir, err)
		}
	}

	// 2. 检查核心证书是否存在，如果不存在则生成所有证书
	serverCertPath := filepath.Join(certDir, serverCertFile)
	if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
		log.Println("未找到服务器证书，开始生成新的 CA、服务器和客户端证书...")
		if err := generateAllCerts(tunnelAddr); err != nil {
			return nil, "", fmt.Errorf("证书生成失败: %w", err)
		}
		log.Println("证书生成成功！")
	} else {
		log.Println("发现现有证书，将加载它们。")
	}

	// 3. 加载服务器证书和私钥
	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, serverCertFile),
		filepath.Join(certDir, serverKeyFile),
	)
	if err != nil {
		return nil, "", fmt.Errorf("无法加载服务器证书/密钥对: %w", err)
	}

	// 4. 加载 CA 证书用于验证客户端
	caCertBytes, err := os.ReadFile(filepath.Join(certDir, caCertFile))
	if err != nil {
		return nil, "", fmt.Errorf("无法加载 CA 证书: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertBytes) {
		return nil, "", fmt.Errorf("无法将 CA 证书添加到池中")
	}

	// 5. 创建服务器的 TLS 配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // 强制要求并验证客户端证书
		MinVersion:   tls.VersionTLS13,               // 推荐使用 TLS 1.3
	}

	// 6. 加载客户端文件内容，准备生成配置字符串
	clientCertBytes, err := os.ReadFile(filepath.Join(certDir, clientCertFile))
	if err != nil {
		return nil, "", fmt.Errorf("无法读取客户端证书: %w", err)
	}
	clientKeyBytes, err := os.ReadFile(filepath.Join(certDir, clientKeyFile))
	if err != nil {
		return nil, "", fmt.Errorf("无法读取客户端私钥: %w", err)
	}

	// 7. 创建并编码客户端配置
	clientCfg := ClientConfig{
		ServerAddr: tunnelAddr,
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

// generateAllCerts 生成所有需要的证书和密钥
func generateAllCerts(tunnelAddr string) error {
	// 生成 CA
	caKey, caCert, err := createCertificate(nil, nil, true, "MyProxy CA")
	if err != nil {
		return fmt.Errorf("创建 CA 失败: %w", err)
	}
	if err := savePEM(filepath.Join(certDir, caCertFile), filepath.Join(certDir, caKeyFile), caCert, caKey); err != nil {
		return err
	}

	// 生成服务器证书，由 CA 签名
	serverKey, serverCert, err := createCertificate(caCert, caKey, false, "MyProxy Server")
	if err != nil {
		return fmt.Errorf("创建服务器证书失败: %w", err)
	}
	if err := savePEM(filepath.Join(certDir, serverCertFile), filepath.Join(certDir, serverKeyFile), serverCert, caKey); err != nil {
		return err
	}

	// 生成客户端证书，由 CA 签名
	clientKey, clientCert, err := createCertificate(caCert, caKey, false, "MyProxy Client")
	if err != nil {
		return fmt.Errorf("创建客户端证书失败: %w", err)
	}
	return savePEM(filepath.Join(certDir, clientCertFile), filepath.Join(certDir, clientKeyFile), clientCert, clientKey)
}

// createCertificate 是一个通用的证书创建函数
func createCertificate(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, commonName string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
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
		NotAfter:     time.Now().AddDate(10, 0, 0), // 10年有效期
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	} else {
		// 为服务器证书添加 IP 和 DNS 名称
		if commonName == "MyProxy Server" {
			// 这里可以添加服务器的公网 IP 或域名
			// 为了通用性，我们添加 localhost 和 127.0.0.1
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.DNSNames = []string{"localhost"}
		}
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

// savePEM 将证书和私钥保存到 PEM 文件
func savePEM(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	// 保存证书
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("无法创建证书文件 %s: %w", certPath, err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}

	// 保存私钥
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

// runServer 启动服务端逻辑
func runServer(listenAddr, tunnelAddr string) {
	log.Printf("服务端模式：隧道监听于 %s，服务监听于 %s", tunnelAddr, listenAddr)

	// 1. 生成/加载证书并获取 TLS 配置和客户端配置字符串
	tlsConfig, clientConfigString, err := generateAndLoadCertificates(tunnelAddr)
	if err != nil {
		log.Fatalf("初始化安全配置失败: %v", err)
	}

	// 打印客户端配置字符串
	fmt.Println("\n========================= CLIENT CONFIGURATION =========================")
	fmt.Println("将以下单行配置字符串完整复制到客户端机器上运行:")
	fmt.Printf("\n./your_program -mode client -config \"%s\"\n\n", clientConfigString)
	fmt.Println("========================================================================")

	// 2. 使用 TLS 监听来自 client 的隧道连接
	tunnelListener, err := tls.Listen("tcp", tunnelAddr, tlsConfig)
	if err != nil {
		log.Fatalf("无法监听 TLS 隧道地址 %s: %v", tunnelAddr, err)
	}
	defer tunnelListener.Close()

	log.Println("等待客户端连接隧道 (mTLS)...")
	tunnelConn, err := tunnelListener.Accept()
	if err != nil {
		log.Fatalf("接受隧道连接失败: %v", err)
	}
	log.Printf("客户端 %s 已通过 mTLS 验证并连接隧道", tunnelConn.RemoteAddr())

	// 3. 使用 smux 在隧道连接上建立会话 (无变化)
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	session, err := smux.Server(tunnelConn, smuxConfig)
	if err != nil {
		log.Fatalf("无法创建 smux 服务端会话: %v", err)
	}
	defer session.Close()

	// 4. 监听供外部工具连接的端口 (无变化)
	serviceListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("无法监听服务地址 %s: %v", listenAddr, err)
	}
	defer serviceListener.Close()
	log.Printf("服务已就绪")

	// 5. 循环接受外部工具的连接 (无变化)
	for {
		userConn, err := serviceListener.Accept()
		if err != nil {
			log.Printf("接受用户连接失败: %v", err)
			continue
		}
		log.Printf("收到新用户连接 %s", userConn.RemoteAddr())
		stream, err := session.OpenStream()
		if err != nil {
			log.Printf("无法在 smux 会话上打开新流: %v", err)
			userConn.Close()
			continue
		}
		go func() {
			defer userConn.Close()
			defer stream.Close()
			handleStream(userConn, stream)
			log.Printf("用户连接 %s 的会话已结束", userConn.RemoteAddr())
		}()
	}
}

// runClient 启动客户端逻辑
func runClient(configString, targetAddr string) {
	// 1. 解码配置字符串
	jsonBytes, err := base64.StdEncoding.DecodeString(configString)
	if err != nil {
		log.Fatalf("无效的配置字符串 (Base64解码失败): %v", err)
	}
	var cfg ClientConfig
	if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
		log.Fatalf("无效的配置字符串 (JSON解析失败): %v", err)
	}

	log.Printf("客户端模式：连接到远程隧道 %s，转发到本地目标 %s", cfg.ServerAddr, targetAddr)

	// 2. 创建客户端 TLS 配置
	clientCert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
	if err != nil {
		log.Fatalf("无法加载客户端证书/密钥对: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(cfg.CACert)) {
		log.Fatal("无法将 CA 证书添加到池中")
	}
	
	// 从服务器地址中提取主机名用于 ServerName
	serverHost, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		// 如果没有端口，假定整个字符串是主机名
		serverHost = cfg.ServerAddr
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   serverHost, // SNI (Server Name Indication)，对于验证服务器证书很重要
		MinVersion:   tls.VersionTLS13,
	}

	// 3. 使用 TLS 主动连接到 server 的隧道端口
	tunnelConn, err := tls.Dial("tcp", cfg.ServerAddr, tlsConfig)
	if err != nil {
		log.Fatalf("无法通过 mTLS 连接到远程隧道 %s: %v", cfg.ServerAddr, err)
	}
	log.Printf("已成功通过 mTLS 连接到隧道 %s", cfg.ServerAddr)

	// 4. 使用 smux 在隧道连接上建立会话 (无变化)
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	session, err := smux.Client(tunnelConn, smuxConfig)
	if err != nil {
		log.Fatalf("无法创建 smux 客户端会话: %v", err)
	}
	defer session.Close()

	// 5. 循环等待 server 通过隧道发来新的流请求 (无变化)
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("无法接受新流: %v", err)
			}
			return // 会话关闭，客户端退出
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

	// Client 模式参数
	configString := flag.String("config", "", "[Client模式] 从服务端获取的单行配置字符串")
	targetAddr := flag.String("target", "localhost:5555", "[Client模式] 要转发流量的本地目标地址")

	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	switch *mode {
	case "server":
		if *tunnelAddr == "" {
			log.Fatal("[Server模式] 必须提供 -tunnel 参数")
		}
		runServer(*listenAddr, *tunnelAddr)
	case "client":
		if *configString == "" {
			log.Fatal("[Client模式] 必须提供 -config 参数")
		}
		runClient(*configString, *targetAddr)
	default:
		fmt.Println("错误: 必须指定模式 -mode 'server' 或 -mode 'client'")
		flag.PrintDefaults()
	}
}
