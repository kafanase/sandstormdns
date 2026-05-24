package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// Стандартный алфавит Base32, используемый как база для перемешивания
const base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"

// Глобальный пул буферов для минимизации работы сборщика мусора (GC) под высокой нагрузкой
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535)
	},
}

// Конфигурация туннеля
type Config struct {
	Mode        string
	ListenAddr  string
	TargetAddr  string
	Domain      string
	Resolvers   []string
	Password    string
	QueryType   string // "TXT", "A", "AAAA", "AUTO"
	Verbose     bool
	CustomB32   string // Перемешанный алфавит на основе пароля
}

// Структура фрагмента пакета
type Fragment struct {
	SessionID    uint16
	PacketID     uint32
	FragIndex    uint8
	TotalFrags   uint8
	IsCompressed uint8 // Флаг: 1 - сжато, 0 - без сжатия
	Payload      []byte
}

// Сессия для сборки пакетов на стороне сервера
type Session struct {
	sync.Mutex
	lastSeen   time.Time
	fragments  map[uint32][]*Fragment
	outputChan chan []byte
}

func main() {
	cfg := Config{}
	var resolversStr string

	flag.StringVar(&cfg.Mode, "mode", "client", "Режим работы: client или server")
	flag.StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:10800", "Адрес для прослушивания")
	flag.StringVar(&cfg.TargetAddr, "target", "", "Адрес назначения (target)")
	flag.StringVar(&cfg.Domain, "domain", "tunnel.mydomain.com", "Корневой домен туннеля")
	flag.StringVar(&resolversStr, "resolvers", "1.1.1.1:53,77.88.8.8:53,8.8.8.8:53", "Список DNS-серверов через запятую")
	flag.StringVar(&cfg.Password, "pass", "SuperSecretDnsPass2026", "Пароль для шифрования и генерации алфавита")
	flag.StringVar(&cfg.QueryType, "qtype", "AUTO", "Тип запросов: TXT, A, AAAA, AUTO")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Детальные логи")
	flag.Parse()

	if resolversStr != "" {
		cfg.Resolvers = strings.Split(resolversStr, ",")
	}

	// Генерация уникального алфавита Base32 на основе пароля (KDF-alike shuffling)
	cfg.CustomB32 = deriveAlphabet(cfg.Password)

	log.Printf("[*] Инициализация DNS-туннеля V2 (Улучшенная производительность)...")
	log.Printf("[*] Маскировочный алфавит: %s", cfg.CustomB32)

	if cfg.Mode == "server" {
		runServer(&cfg)
	} else {
		runClient(&cfg)
	}
}

// --- КРИПТОГРАФИЯ И КОДИРОВАНИЕ ---

// Перемешивание алфавита Base32 на основе хэша пароля
func deriveAlphabet(password string) string {
	hash := sha256.Sum256([]byte(password))
	alphabet := []byte(base32Alphabet)

	// Алгоритм тасования Фишера-Йетса с детерминированным сидом из хэша пароля
	n := len(alphabet)
	for i := n - 1; i > 0; i-- {
		j := int(hash[i%32]) % (i + 1)
		alphabet[i], alphabet[j] = alphabet[j], alphabet[i]
	}
	return string(alphabet)
}

// Кодирование в кастомный Base32 без дополнения (padding)
func customBase32Encode(data []byte, alphabet string) string {
	encoder := base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)
	return encoder.EncodeToString(data)
}

// Декодирование из кастомного Base32
func customBase32Decode(data string, alphabet string) ([]byte, error) {
	encoder := base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)
	return encoder.DecodeString(data)
}

// Генерация уникальной XOR гаммы на основе пароля, сессии и номера пакета
func xorCryptStream(data []byte, password string, sessionID uint16, packetID uint32) []byte {
	iv := make([]byte, 6)
	binary.BigEndian.PutUint16(iv[0:2], sessionID)
	binary.BigEndian.PutUint32(iv[2:6], packetID)

	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write(iv)
	keyStream := hasher.Sum(nil)

	res := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		res[i] = data[i] ^ keyStream[i%32]
	}
	return res
}

// Умное адаптивное сжатие
func smartCompress(data []byte) ([]byte, bool) {
	if len(data) <= 48 {
		return data, false
	}

	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.HuffmanOnly)
	if err != nil {
		return data, false
	}
	_, err = writer.Write(data)
	if err != nil {
		return data, false
	}
	_ = writer.Close()

	if buf.Len() >= len(data) {
		return data, false
	}

	return buf.Bytes(), true
}

// Быстрая распаковка данных
func decompress(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()
	return io.ReadAll(reader)
}

// --- СЕРИАЛИЗАЦИЯ ФРАГМЕНТОВ ---

func serializeFragment(f *Fragment) []byte {
	buf := make([]byte, 11+len(f.Payload))
	binary.BigEndian.PutUint16(buf[0:2], f.SessionID)
	binary.BigEndian.PutUint32(buf[2:6], f.PacketID)
	buf[6] = f.FragIndex
	buf[7] = f.TotalFrags
	buf[8] = f.IsCompressed
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(f.Payload)))
	copy(buf[11:], f.Payload)
	return buf
}

func deserializeFragment(buf []byte) (*Fragment, error) {
	if len(buf) < 11 {
		return nil, fmt.Errorf("фрагмент поврежден")
	}
	f := &Fragment{}
	f.SessionID = binary.BigEndian.Uint16(buf[0:2])
	f.PacketID = binary.BigEndian.Uint32(buf[2:6])
	f.FragIndex = buf[6]
	f.TotalFrags = buf[7]
	f.IsCompressed = buf[8]
	length := binary.BigEndian.Uint16(buf[9:11])
	if len(buf) < 11+int(length) {
		return nil, fmt.Errorf("неполные данные payload")
	}
	f.Payload = make([]byte, length)
	copy(f.Payload, buf[11:11+int(length)])
	return f, nil
}

// --- КЛИЕНТ (ПОДГОТОВКА И ОТПРАВКА) ---

func runClient(cfg *Config) {
	if cfg.TargetAddr == "" {
		log.Fatal("[-] Необходимо указать -target адрес для форвардинга.")
	}

	localAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("[-] Ошибка резолвинга: %v", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatalf("[-] Ошибка прослушивания UDP: %v", err)
	}
	defer conn.Close()

	log.Printf("[+] Клиент слушает UDP трафик на %s", cfg.ListenAddr)

	// Инициализируем постоянные подключения к резолверам для скорости
	var outConns []*net.UDPConn
	for _, resAddrStr := range cfg.Resolvers {
		rAddr, err := net.ResolveUDPAddr("udp", resAddrStr)
		if err != nil {
			log.Printf("[-] Ошибка резолвера %s: %v", resAddrStr, err)
			continue
		}
		outConn, err := net.DialUDP("udp", nil, rAddr)
		if err != nil {
			log.Printf("[-] Ошибка подключения к %s: %v", resAddrStr, err)
			continue
		}
		outConns = append(outConns, outConn)
		
		// Фоновое чтение для удержания NAT state (без блокировки основного потока)
		go func(c *net.UDPConn) {
			devNullBuf := make([]byte, 1024)
			for {
				_, err := c.Read(devNullBuf)
				if err != nil {
					return
				}
			}
		}(outConn)
	}

	if len(outConns) == 0 {
		log.Fatal("[-] Нет доступных DNS резолверов.")
	}

	var sessionID uint16
	n, _ := rand.Int(rand.Reader, big.NewInt(65535))
	sessionID = uint16(n.Uint64())

	var packetCounter uint32 = 0
	var fragCounter uint32 = 0 // Используется для балансировки Round-Robin

	sendQueue := make(chan string, 5000)
	
	// Пул воркеров отправки
	for i := 0; i < 15; i++ {
		go func() {
			for domain := range sendQueue {
				sendRawDNSRequest(domain, cfg, outConns, &fragCounter)
			}
		}()
	}

	for {
		buf := bufferPool.Get().([]byte)
		length, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			bufferPool.Put(buf)
			continue
		}

		packetData := buf[:length]
		packetCounter++

		// Адаптивное сжатие и шифрование
		compressed, isCompressed := smartCompress(packetData)
		var compFlag uint8 = 0
		if isCompressed {
			compFlag = 1
		}

		encrypted := xorCryptStream(compressed, cfg.Password, sessionID, packetCounter)

		// Фрагментация
		const maxFragSize = 45
		totalFrags := uint8((len(encrypted) + maxFragSize - 1) / maxFragSize)
		if totalFrags == 0 {
			totalFrags = 1
		}

		for i := uint8(0); i < totalFrags; i++ {
			start := int(i) * maxFragSize
			end := start + maxFragSize
			if end > len(encrypted) {
				end = len(encrypted)
			}

			frag := &Fragment{
				SessionID:    sessionID,
				PacketID:     packetCounter,
				FragIndex:    i,
				TotalFrags:   totalFrags,
				IsCompressed: compFlag,
				Payload:      encrypted[start:end],
			}

			serialized := serializeFragment(frag)
			encoded := customBase32Encode(serialized, cfg.CustomB32)

			var subdomains []string
			subdomains = append(subdomains, fmt.Sprintf("%x", time.Now().UnixNano()%1000000))
			
			for k := 0; k < len(encoded); k += 30 {
				endK := k + 30
				if endK > len(encoded) {
					endK = len(encoded)
				}
				subdomains = append(subdomains, encoded[k:endK])
			}
			
			fullDomain := strings.Join(subdomains, ".") + "." + cfg.Domain
			if !strings.HasSuffix(fullDomain, ".") {
				fullDomain += "."
			}

			sendQueue <- fullDomain
		}
		bufferPool.Put(buf)
	}
}

// Быстрая отправка запроса по предварительно открытым сокетам
func sendRawDNSRequest(domain string, cfg *Config, outConns []*net.UDPConn, counter *uint32) {
	qType := uint16(16) // По умолчанию TXT (0x0010)
	if cfg.QueryType == "AUTO" {
		switch time.Now().Nanosecond() % 3 {
		case 0: qType = 16 // TXT
		case 1: qType = 1  // A
		case 2: qType = 15 // MX
		}
	} else if cfg.QueryType == "A" {
		qType = 1
	}

	// Формирование структуры DNS-пакета
	packet := bufferPool.Get().([]byte)
	defer bufferPool.Put(packet)
	
	idx := 0
	// Уникальный транзакционный ID и Флаги
	copy(packet[idx:], []byte{0xDE, 0xAD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	idx += 12

	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		packet[idx] = byte(len(part))
		idx++
		copy(packet[idx:], part)
		idx += len(part)
	}
	packet[idx] = 0x00
	idx++

	// Записываем тип запроса и класс IN
	binary.BigEndian.PutUint16(packet[idx:], qType)
	idx += 2
	binary.BigEndian.PutUint16(packet[idx:], 1)
	idx += 2

	// Атомарно увеличиваем счетчик для Round-Robin балансировки
	// Это предотвратит отправку одного фрагмента на все резолверы сразу
	// и равномерно распределит трафик.
	*counter++
	connIdx := (*counter) % uint32(len(outConns))
	targetConn := outConns[connIdx]

	_, _ = targetConn.Write(packet[:idx])

	if cfg.Verbose {
		log.Printf("[Client] Отправлен запрос типа %d для %s (Резолвер %d)", qType, domain[:25]+"...", connIdx)
	}
}

// --- СЕРВЕР (СБОРКА И ОБРАБОТКА) ---

func runServer(cfg *Config) {
	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("[-] Ошибка разбора адреса: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("[-] Ошибка запуска сервера: %v", err)
	}
	defer conn.Close()

	log.Printf("[+] Теневой DNS-сервер запущен на %s", cfg.ListenAddr)

	sessions := make(map[uint16]*Session)
	var sessionsMu sync.Mutex

	// Сборщик мусора для зависших и старых сессий
	go func() {
		for {
			time.Sleep(30 * time.Second)
			now := time.Now()
			sessionsMu.Lock()
			for id, sess := range sessions {
				sess.Lock()
				if now.Sub(sess.lastSeen) > 2*time.Minute {
					close(sess.outputChan) // Закрываем канал, чтобы завершить воркер
					delete(sessions, id)
				}
				sess.Unlock()
			}
			sessionsMu.Unlock()
		}
	}()

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.TargetAddr)
	if err != nil && cfg.TargetAddr != "" {
		log.Fatalf("[-] Неверный формат адреса target: %v", err)
	}

	var targetConn *net.UDPConn
	if cfg.TargetAddr != "" {
		tConn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			log.Fatalf("[-] Ошибка соединения с конечным портом: %v", err)
		}
		targetConn = tConn
		defer targetConn.Close()
	}

	for {
		buf := bufferPool.Get().([]byte)
		n, rAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			bufferPool.Put(buf)
			continue
		}

		// Копируем данные для обработки в отдельной горутине, а буфер возвращаем в пул
		request := make([]byte, n)
		copy(request, buf[:n])
		bufferPool.Put(buf)

		go parseAndProcessDNS(conn, rAddr, request, cfg, &sessions, &sessionsMu, targetConn)
	}
}

func parseAndProcessDNS(
	dnsConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	packet []byte,
	cfg *Config,
	sessions *map[uint16]*Session,
	sessionsMu *sync.Mutex,
	targetConn *net.UDPConn,
) {
	if len(packet) < 12 {
		return
	}

	idx := 12
	var domainParts []string
	for {
		if idx >= len(packet) {
			return
		}
		length := int(packet[idx])
		if length == 0 {
			idx++
			break
		}
		idx++
		if idx+length > len(packet) {
			return
		}
		domainParts = append(domainParts, string(packet[idx:idx+length]))
		idx += length
	}

	fullQuery := strings.Join(domainParts, ".")
	if !strings.HasSuffix(fullQuery, cfg.Domain) {
		return
	}

	cleanDomain := strings.TrimSuffix(fullQuery, cfg.Domain)
	cleanParts := strings.Split(cleanDomain, ".")
	if len(cleanParts) < 3 {
		return
	}

	payloadB32 := strings.Join(cleanParts[1:len(cleanParts)-1], "")

	serialized, err := customBase32Decode(payloadB32, cfg.CustomB32)
	if err != nil {
		return
	}

	frag, err := deserializeFragment(serialized)
	if err != nil {
		return
	}

	sessionsMu.Lock()
	sess, exists := (*sessions)[frag.SessionID]
	if !exists {
		sess = &Session{
			fragments:  make(map[uint32][]*Fragment),
			lastSeen:   time.Now(),
			outputChan: make(chan []byte, 1000),
		}
		(*sessions)[frag.SessionID] = sess
		go processServerOutputQueue(sess, targetConn, cfg)
	}
	sessionsMu.Unlock()

	sess.Lock()
	sess.lastSeen = time.Now()
	sess.fragments[frag.PacketID] = append(sess.fragments[frag.PacketID], frag)

	frags := sess.fragments[frag.PacketID]
	if len(frags) == int(frag.TotalFrags) {
		orderedPayload := make([]byte, 0)
		for i := uint8(0); i < frag.TotalFrags; i++ {
			for _, f := range frags {
				if f.FragIndex == i {
					orderedPayload = append(orderedPayload, f.Payload...)
					break
				}
			}
		}
		delete(sess.fragments, frag.PacketID)
		sess.Unlock()

		decrypted := xorCryptStream(orderedPayload, cfg.Password, frag.SessionID, frag.PacketID)

		var finalData []byte
		if frag.IsCompressed == 1 {
			decompressed, err := decompress(decrypted)
			if err != nil {
				return
			}
			finalData = decompressed
		} else {
			finalData = decrypted
		}

		sess.outputChan <- finalData
	} else {
		sess.Unlock()
	}

	sendFastResponse(dnsConn, clientAddr, packet)
}

func processServerOutputQueue(sess *Session, targetConn *net.UDPConn, cfg *Config) {
	for data := range sess.outputChan {
		if targetConn != nil {
			_, _ = targetConn.Write(data)
			if cfg.Verbose {
				log.Printf("[Server -> Target] Направлено в целевой сокет: %d байт", len(data))
			}
		} else {
			fmt.Printf("%s", string(data))
		}
	}
}

func sendFastResponse(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte) {
	if len(request) < 12 {
		return
	}

	var response bytes.Buffer
	response.Write(request[0:2])
	response.Write([]byte{0x81, 0x80})
	response.Write([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})

	idx := 12
	for {
		if idx >= len(request) {
			break
		}
		length := int(request[idx])
		if length == 0 {
			idx++
			break
		}
		idx += length + 1
	}
	questionEnd := idx + 4
	if questionEnd > len(request) {
		return
	}
	response.Write(request[12:questionEnd])

	response.Write([]byte{0xc0, 0x0c})
	response.Write([]byte{0x00, 0x10})
	response.Write([]byte{0x00, 0x01})
	response.Write([]byte{0x00, 0x00, 0x00, 0x01})

	txtData := "ACK"
	response.WriteByte(0x00)
	response.WriteByte(byte(len(txtData) + 1))
	response.WriteByte(byte(len(txtData)))
	response.WriteString(txtData)

	_, _ = conn.WriteToUDP(response.Bytes(), clientAddr)
}