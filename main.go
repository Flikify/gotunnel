package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	// 使用 crypto/rand 下的 mathrand.Intn 来避免锁定全局随机数生成器
	cryptorand "crypto/rand"
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
	"math/rand" // 用于抖动
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// ... (从 const certDir 到 savePEM 函数的代码保持不变，这里省略)
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

// ControlMessage 是客户端发送给服务端的控制消息，用于请求端口转发
type ControlMessage struct {
	RemotePort int `json:"remote_port"`
}

// ControlResponse 是服务端响应给客户端的控制消息
type ControlResponse struct {
	Status  string `json:"status"` // "success" or "error"
	Message string `json:"message"`
}

// handleStream 负责在两个连接之间双向拷贝数据，并优雅地处理关闭
func handleStream(p1, p2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(p2, p1)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("数据拷贝时出错 (p1->p2): %v", err)
		}
		if conn, ok := p2.(interface{ CloseWrite() error }); ok {
			_ = conn.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(p1, p2)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("数据拷贝时出错 (p2->p1): %v", err)
		}
		if conn, ok := p1.(interface{ CloseWrite() error }); ok {
			_ = conn.CloseWrite()
		}
	}()
	wg.Wait()
}

// generateAndLoadCertificates 负责生成（如果需要）并加载所有证书
func generateAndLoadCertificates(publicAddr string) (*tls.Config, string, error) {
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		if err := os.Mkdir(certDir, 0700); err != nil {
			return nil, "", fmt.Errorf("无法创建证书目录 %s: %w", certDir, err)
		}
	}

	serverCertPath := filepath.Join(certDir, serverCertFile)
	if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
		log.Println("未找到服务器证书，开始生成新的 CA、服务器和客户端证书...")
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
		ServerAddr: publicAddr,
		CACert:     string(caCertBytes),
		ClientCert: string(clientCertBytes),
		ClientKey:  string(clientKeyBytes),
	}
	jsonBytes, err := json.Marshal(clientCfg)
	if err != nil {
		return nil, "", fmt.Errorf("无法序列化客户端配置到 JSON: %w", err)
	}
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(jsonBytes); err != nil {
		return nil, "", fmt.Errorf("压缩配置数据失败: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, "", fmt.Errorf("关闭 gzip writer 失败: %w", err)
	}
	configString := base64.RawStdEncoding.EncodeToString(b.Bytes())

	return tlsConfig, configString, nil
}

func generateAllCerts(publicAddr string) error {
	caKey, caCert, err := createCertificate(nil, nil, true, "MyProxy CA", nil, nil)
	if err != nil {
		return fmt.Errorf("创建 CA 失败: %w", err)
	}
	if err := savePEM(filepath.Join(certDir, caCertFile), filepath.Join(certDir, caKeyFile), caCert, caKey); err != nil {
		return err
	}
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

func createCertificate(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, commonName string, ips []net.IP, dnsNames []string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cryptorand.Int(cryptorand.Reader, serialNumberLimit)
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
	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &template, ca, &privateKey.PublicKey, signingKey)
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

// ======================= 服务端逻辑 (未修改) =======================
func runServer(tunnelAddr, publicAddr string) {
	// ... 这部分代码保持不变 ...
	log.Printf("服务端模式：隧道监听于 %s, 公网地址为 %s", tunnelAddr, publicAddr)

	tlsConfig, clientConfigString, err := generateAndLoadCertificates(publicAddr)
	if err != nil {
		log.Fatalf("初始化安全配置失败: %v", err)
	}

	fmt.Println("\n========================= CLIENT CONFIGURATION =========================")
	fmt.Println("将以下单行配置字符串完整复制到客户端机器上运行，并根据需要添加 -remote-port 和 -local-target 参数:")
	fmt.Printf("\n./gotunnel -mode client -config \"%s\" -remote-port 8080 -local-target 127.0.0.1:5037\n\n", clientConfigString)
	fmt.Println("========================================================================")

	tunnelListener, err := tls.Listen("tcp", tunnelAddr, tlsConfig)
	if err != nil {
		log.Fatalf("无法监听 TLS 隧道地址 %s: %v", tunnelAddr, err)
	}
	defer tunnelListener.Close()

	for {
		log.Println("等待客户端连接隧道 (mTLS)...")
		tunnelConn, err := tunnelListener.Accept()
		if err != nil {
			log.Printf("接受隧道连接失败: %v", err)
			continue
		}
		// 每个客户端连接都是一个独立的会话
		go handleClientSession(tunnelConn)
	}
}

func handleClientSession(tunnelConn net.Conn) {
	// ... 这部分代码保持不变 ...
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

	// 1. 等待客户端的第一个流，作为控制流
	log.Printf("[%s] 等待客户端发送控制指令...", tunnelConn.RemoteAddr())
	controlStream, err := session.AcceptStream()
	if err != nil {
		log.Printf("[%s] 接受控制流失败: %v", tunnelConn.RemoteAddr(), err)
		return
	}
	defer controlStream.Close()

	// 2. 解析控制消息
	var ctrlMsg ControlMessage
	if err := json.NewDecoder(controlStream).Decode(&ctrlMsg); err != nil {
		log.Printf("[%s] 解析控制消息失败: %v", tunnelConn.RemoteAddr(), err)
		_ = json.NewEncoder(controlStream).Encode(ControlResponse{Status: "error", Message: "Invalid control message"})
		return
	}
	log.Printf("[%s] 收到控制指令：请求转发公网端口 :%d", tunnelConn.RemoteAddr(), ctrlMsg.RemotePort)

	// 3. 尝试监听客户端请求的公网端口
	publicListenAddr := fmt.Sprintf(":%d", ctrlMsg.RemotePort)
	publicListener, err := net.Listen("tcp", publicListenAddr)
	if err != nil {
		errMsg := fmt.Sprintf("监听公网端口 %s 失败: %v", publicListenAddr, err)
		log.Printf("[%s] %s", tunnelConn.RemoteAddr(), errMsg)
		_ = json.NewEncoder(controlStream).Encode(ControlResponse{Status: "error", Message: errMsg})
		return
	}
	defer publicListener.Close()

	// 4. 发送成功响应给客户端
	successMsg := fmt.Sprintf("成功在 %s 上监听, 准备转发流量", publicListener.Addr().String())
	log.Printf("[%s] %s", tunnelConn.RemoteAddr(), successMsg)
	err = json.NewEncoder(controlStream).Encode(ControlResponse{Status: "success", Message: successMsg})
	if err != nil {
		log.Printf("[%s] 发送成功响应失败: %v", tunnelConn.RemoteAddr(), err)
		return
	}
	controlStream.Close()

	// 5. 循环接受公网连接，并通过smux session转发
	log.Printf("[%s] 开始为 %s 接受公网连接...", tunnelConn.RemoteAddr(), publicListener.Addr())
	for {
		if session.IsClosed() {
			log.Printf("[%s] 客户端会话已关闭，停止为其接受新用户连接。", tunnelConn.RemoteAddr())
			return
		}

		userConn, err := publicListener.Accept()
		if err != nil {
			if session.IsClosed() || strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Printf("[%s] 接受公网用户连接失败: %v", tunnelConn.RemoteAddr(), err)
			continue
		}
		log.Printf("[%s] 收到新公网连接 %s，将通过隧道转发", tunnelConn.RemoteAddr(), userConn.RemoteAddr())

		dataStream, err := session.OpenStream()
		if err != nil {
			log.Printf("[%s] 无法在 smux 会话上打开新流: %v", tunnelConn.RemoteAddr(), err)
			userConn.Close()
			return
		}

		go func() {
			defer userConn.Close()
			defer dataStream.Close()
			handleStream(userConn, dataStream)
			log.Printf("[%s] 公网连接 %s 的会话已结束", tunnelConn.RemoteAddr(), userConn.RemoteAddr())
		}()
	}
}

// ======================= 客户端逻辑 (已修改) =======================

func runClient(configString, localTargetAddr string, remotePort int, maxRetryInterval time.Duration) {
	// [修改] 解析配置的逻辑只执行一次
	compressedBytes, err := base64.RawStdEncoding.DecodeString(configString)
	if err != nil {
		log.Fatalf("无效的配置字符串 (Base64解码失败): %v", err)
	}
	r, err := gzip.NewReader(bytes.NewReader(compressedBytes))
	if err != nil {
		log.Fatalf("无法创建 gzip reader: %v", err)
	}
	jsonBytes, err := io.ReadAll(r)
	if err != nil {
		log.Fatalf("解压配置数据失败: %v", err)
	}
	_ = r.Close()

	var cfg ClientConfig
	if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
		log.Fatalf("无效的配置字符串 (JSON解析失败): %v", err)
	}

	clientCert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
	if err != nil {
		log.Fatalf("无法加载客户端证书/密钥对: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(cfg.CACert)) {
		log.Fatal("无法将 CA 证书添加到池中")
	}
	serverHost, _, _ := net.SplitHostPort(cfg.ServerAddr)
	if serverHost == "" {
		serverHost = cfg.ServerAddr
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   serverHost,
		MinVersion:   tls.VersionTLS13,
	}

	log.Printf("客户端模式启动：目标服务端 %s", cfg.ServerAddr)
	log.Printf("-> 远程端口 :%d -> 本地目标 %s", remotePort, localTargetAddr)

	// [新增] 自动重连的主循环
	var currentRetryInterval = 2 * time.Second
	for {
		// 1. 尝试连接，直到成功
		var tunnelConn net.Conn
		for {
			log.Printf("正在尝试连接到服务端 %s...", cfg.ServerAddr)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			d := tls.Dialer{Config: tlsConfig}
			conn, err := d.DialContext(ctx, "tcp", cfg.ServerAddr)
			cancel() // 及时释放 context 资源

			if err == nil {
				log.Println("成功连接到服务端！")
				tunnelConn = conn
				currentRetryInterval = 2 * time.Second // 连接成功后，重置重试间隔
				break
			}

			log.Printf("连接失败: %v", err)
			log.Printf("将在 %.0f 秒后重试...", currentRetryInterval.Seconds())
			time.Sleep(currentRetryInterval)

			// 指数退避策略
			currentRetryInterval *= 2
			// 增加抖动，防止惊群效应
			jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
			currentRetryInterval += jitter

			if currentRetryInterval > maxRetryInterval {
				currentRetryInterval = maxRetryInterval
			}
		}

		// 2. 连接成功后，运行核心业务逻辑
		runClientSession(tunnelConn, localTargetAddr, remotePort)

		// 3. 如果 `runClientSession` 返回，说明连接已断开
		log.Println("与服务端的连接已断开，准备自动重连...")
		// 短暂等待后，循环将自动开始下一次连接尝试
		time.Sleep(2 * time.Second)
	}
}

// [新增] runClientSession 封装了单次连接成功后的所有操作
func runClientSession(tunnelConn net.Conn, localTargetAddr string, remotePort int) {
	defer tunnelConn.Close()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	session, err := smux.Client(tunnelConn, smuxConfig)
	if err != nil {
		log.Printf("创建 smux 客户端会话失败: %v", err)
		return // 返回后将触发重连
	}
	defer session.Close()

	if err := requestPortForwarding(session, remotePort); err != nil {
		log.Printf("请求端口转发失败: %v", err)
		return // 返回后将触发重连
	}

	log.Println("控制指令发送成功，开始监听并转发流量...")
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "broken pipe") {
				log.Println("隧道会话已关闭。")
			} else {
				log.Printf("无法接受新流: %v", err)
			}
			return // 任何错误都将导致返回，并触发外部的重连逻辑
		}

		go func() {
			log.Println("收到新的转发请求，正在连接本地服务...")
			localConn, err := net.Dial("tcp", localTargetAddr)
			if err != nil {
				log.Printf("无法连接到本地目标 %s: %v", localTargetAddr, err)
				_ = stream.Close()
				return
			}
			defer localConn.Close()
			defer stream.Close()
			handleStream(localConn, stream)
			log.Println("本地转发会话已结束")
		}()
	}
}

// requestPortForwarding 客户端通过smux会话发送控制指令
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
	log.Printf("控制消息已发送: %+v", req)

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

func main() {
	// [新增] main函数中初始化随机数种子
	rand.Seed(time.Now().UnixNano())

	mode := flag.String("mode", "", "运行模式: 'server' 或 'client'")

	// Server 模式参数
	tunnelAddr := flag.String("tunnel", ":7000", "[Server模式] 用于监听客户端隧道的地址")
	publicAddr := flag.String("public-addr", "", "[Server模式-必需] 服务器的公网地址和隧道端口 (例如: myproxy.com:7000)")

	// Client 模式参数
	configString := flag.String("config", "", "[Client模式-必需] 从服务端获取的单行配置字符串")
	localTargetAddr := flag.String("local-target", "127.0.0.1:5037", "[Client模式] 要转发流量的本地目标地址")
	remotePort := flag.Int("remote-port", 8080, "[Client模式] 希望在服务端暴露的公网端口")
	// [新增] 客户端重连相关的参数
	maxRetryInterval := flag.Duration("max-retry-interval", 60*time.Second, "[Client模式] 自动重连的最大等待间隔")

	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	switch *mode {
	case "server":
		if *publicAddr == "" {
			log.Fatal("[Server模式] 错误: 必须提供 -public-addr 参数")
		}
		runServer(*tunnelAddr, *publicAddr)
	case "client":
		if *configString == "" {
			log.Fatal("[Client模式] 错误: 必须提供 -config 参数")
		}
		if *remotePort <= 0 || *remotePort > 65535 {
			log.Fatal("[Client模式] 错误: -remote-port 必须是 1-65535 之间的有效端口")
		}
		// [修改] 将最大重试间隔传递给 runClient
		runClient(*configString, *localTargetAddr, *remotePort, *maxRetryInterval)
	default:
		fmt.Println("错误: 必须指定模式 -mode 'server' 或 -mode 'client'")
		flag.PrintDefaults()
	}
}
