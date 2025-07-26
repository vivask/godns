// godns/internal/server/vrrp/vrrp.go
package vrrp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"godns/internal/config"
	"godns/internal/log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/packet"
)

const (
	VRRP_PROTO_NUM   = 112
	VRRP_VERSION     = 2
	VRRP_TYPE_ADVERT = 1
	VRRP_PRIO_OWNER  = 255
	VRRP_PRIO_DFL    = 100
	VRRP_PRIO_STOP   = 0
)

type VRRP struct {
	cfg        *config.Config
	iface      *net.Interface
	conn       *packet.Conn
	vip        net.IP
	master     bool
	priority   uint
	vrid       uint
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	lastAdvert time.Time
}

type VRRPHeader struct {
	VersionType uint8    // Version (4 bits) + Type (4 bits)
	VRID        uint8    // Virtual Router ID
	Priority    uint8    // Router Priority
	CountIP     uint8    // Number of IP addresses
	AuthType    uint8    // Authentication Type
	AdverInt    uint8    // Advertisement Interval (in seconds)
	Checksum    uint16   // Checksum
	IPs         []net.IP // IP addresses
}

func New(cfg *config.Config) (*VRRP, error) {
	if !cfg.Vrrp.Enable {
		return nil, nil
	}

	iface, err := net.InterfaceByName(cfg.Vrrp.Iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", cfg.Vrrp.Iface, err)
	}

	vip := net.ParseIP(cfg.Vrrp.Vip)
	if vip == nil {
		return nil, fmt.Errorf("invalid VIP address: %s", cfg.Vrrp.Vip)
	}

	// Создаем packet socket для работы с VRRP пакетами
	conn, err := packet.Listen(iface, packet.Raw, int(layers.EthernetTypeIPv4), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create packet socket: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	v := &VRRP{
		cfg:      cfg,
		iface:    iface,
		conn:     conn,
		vip:      vip,
		priority: uint(cfg.Vrrp.Prior),
		vrid:     uint(cfg.Vrrp.Vrid),
		ctx:      ctx,
		cancel:   cancel,
		master:   false,
	}

	return v, nil
}

func (v *VRRP) Start() error {
	if v == nil {
		return nil
	}

	// Начинаем как backup
	v.master = false
	log.Infof("VRRP started on interface %s, VRID %d, priority %d",
		v.iface.Name, v.vrid, v.priority)

	// Запуск goroutine для прослушивания VRRP пакетов
	go v.listen()

	// Запуск goroutine для отправки advertisement пакетов (если мастер)
	go v.advertise()

	// Запуск goroutine для проверки состояния
	go v.monitor()

	return nil
}

func (v *VRRP) Stop() error {
	if v == nil {
		return nil
	}

	v.cancel()
	if v.conn != nil {
		v.conn.Close()
	}

	// Отправляем shutdown advertisement если мы мастер
	if v.IsMaster() {
		v.sendAdvertisement(VRRP_PRIO_STOP)
		v.releaseVIP()
	}

	log.Info("VRRP stopped")
	return nil
}

func (v *VRRP) IsMaster() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.master
}

func (v *VRRP) listen() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-v.ctx.Done():
			return
		default:
		}

		n, _, err := v.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-v.ctx.Done():
				return
			default:
				log.Warnf("VRRP read error: %v", err)
				continue
			}
		}

		if err := v.handlePacket(buf[:n]); err != nil {
			log.Debugf("VRRP packet handling error: %v", err)
		}
	}
}

func (v *VRRP) handlePacket(data []byte) error {
	// Парсим Ethernet фрейм
	ethLayer := &layers.Ethernet{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, ethLayer)
	decoded := []gopacket.LayerType{}

	if err := parser.DecodeLayers(data, &decoded); err != nil {
		return fmt.Errorf("failed to decode ethernet frame: %w", err)
	}

	// Проверяем, что это IP пакет
	if ethLayer.EthernetType != layers.EthernetTypeIPv4 {
		return nil
	}

	// Находим IP слой
	var ipLayer *layers.IPv4
	for _, layerType := range decoded {
		if layerType == layers.LayerTypeIPv4 {
			ipLayer = &layers.IPv4{}
			break
		}
	}

	if ipLayer == nil {
		return nil
	}

	// Проверяем, что это VRRP протокол
	if ipLayer.Protocol != VRRP_PROTO_NUM {
		return nil
	}

	// Парсим VRRP пакет
	vrrpHdr, err := v.parseVRRPPacket(ipLayer.Payload)
	if err != nil {
		return fmt.Errorf("failed to parse VRRP packet: %w", err)
	}

	// Проверяем VRID
	if uint(vrrpHdr.VRID) != v.vrid {
		return nil
	}

	// Обрабатываем advertisement
	v.processAdvertisement(vrrpHdr)

	return nil
}

func (v *VRRP) parseVRRPPacket(data []byte) (*VRRPHeader, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("VRRP packet too short")
	}

	hdr := &VRRPHeader{
		VersionType: data[0],
		VRID:        data[1],
		Priority:    data[2],
		CountIP:     data[3],
		AuthType:    data[4],
		AdverInt:    data[5],
		Checksum:    uint16(data[6])<<8 | uint16(data[7]),
	}

	version := hdr.VersionType >> 4
	msgType := hdr.VersionType & 0x0F

	if version != VRRP_VERSION || msgType != VRRP_TYPE_ADVERT {
		return nil, fmt.Errorf("unsupported VRRP version/type: %d/%d", version, msgType)
	}

	// Парсим IP адреса
	expectedLen := 8 + int(hdr.CountIP)*4
	if len(data) < expectedLen {
		return nil, fmt.Errorf("VRRP packet too short for IPs")
	}

	for i := 0; i < int(hdr.CountIP); i++ {
		start := 8 + i*4
		ip := net.IP(data[start : start+4])
		hdr.IPs = append(hdr.IPs, ip)
	}

	// Проверяем контрольную сумму
	if !v.verifyChecksum(data) {
		return nil, fmt.Errorf("invalid VRRP checksum")
	}

	return hdr, nil
}

func (v *VRRP) verifyChecksum(data []byte) bool {
	// Создаем копию данных для вычисления контрольной суммы
	checksumData := make([]byte, len(data))
	copy(checksumData, data)

	// Обнуляем поле контрольной суммы
	checksumData[6] = 0
	checksumData[7] = 0

	// Вычисляем контрольную сумму
	calculated := v.calculateChecksum(checksumData)
	actual := uint16(data[6])<<8 | uint16(data[7])

	return calculated == actual
}

func (v *VRRP) calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	// Если нечетное количество байт, добавляем последний байт
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Складываем переносы
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Инвертируем результат
	return ^uint16(sum)
}

func (v *VRRP) processAdvertisement(hdr *VRRPHeader) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.lastAdvert = time.Now()

	// Если приоритет 0 - другой узел выходит из строя
	if hdr.Priority == 0 {
		if !v.master {
			log.Infof("Other master left, attempting to become master")
			v.becomeMaster()
		}
		return
	}

	// Если мы мастер и получили advertisement с более высоким приоритетом
	if v.master {
		if uint(hdr.Priority) > v.priority ||
			(uint(hdr.Priority) == v.priority && hdr.IPs[0].String() > v.vip.String()) {
			log.Infof("Higher priority node detected, becoming backup")
			v.becomeBackup()
		}
	} else {
		// Мы backup, просто обновляем время последнего advertisement
	}
}

func (v *VRRP) advertise() {
	if v.priority == VRRP_PRIO_OWNER {
		// Владелец VIP всегда мастер
		v.mu.Lock()
		v.master = true
		v.mu.Unlock()
		v.announceVIP()
	}

	ticker := time.NewTicker(time.Duration(v.cfg.Vrrp.AdverInt) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			v.mu.RLock()
			isMaster := v.master
			v.mu.RUnlock()

			if isMaster {
				v.sendAdvertisement(uint8(v.priority))
			}
		}
	}
}

func (v *VRRP) sendAdvertisement(priority uint8) error {
	// Создаем VRRP пакет
	vrrpData := make([]byte, 12) // 8 байт заголовка + 4 байта VIP
	vrrpData[0] = (VRRP_VERSION << 4) | VRRP_TYPE_ADVERT
	vrrpData[1] = uint8(v.vrid)
	vrrpData[2] = priority
	vrrpData[3] = 1                          // CountIP
	vrrpData[4] = 0                          // AuthType - none
	vrrpData[5] = uint8(v.cfg.Vrrp.AdverInt) // AdverInt

	// IP адреса
	copy(vrrpData[8:12], v.vip.To4())

	// Вычисляем контрольную сумму
	checksum := v.calculateChecksum(vrrpData)
	vrrpData[6] = byte(checksum >> 8)
	vrrpData[7] = byte(checksum & 0xFF)

	// Создаем IP пакет
	ipHdr := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     20 + uint16(len(vrrpData)),
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        255,
		Protocol:   VRRP_PROTO_NUM,
		SrcIP:      v.getInterfaceIP(),        // Получаем IP интерфейса
		DstIP:      net.ParseIP("224.0.0.18"), // VRRP multicast адрес
	}

	// Создаем Ethernet фрейм
	ethHdr := &layers.Ethernet{
		SrcMAC:       v.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x12}, // VRRP multicast MAC
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Собираем пакет
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, opts,
		ethHdr,
		ipHdr,
		gopacket.Payload(vrrpData),
	); err != nil {
		return fmt.Errorf("failed to serialize VRRP packet: %w", err)
	}

	// Отправляем пакет
	_, err := v.conn.WriteTo(buffer.Bytes(), &packet.Addr{HardwareAddr: ethHdr.DstMAC})
	if err != nil {
		return fmt.Errorf("failed to send VRRP packet: %w", err)
	}

	return nil
}

func (v *VRRP) getInterfaceIP() net.IP {
	addrs, err := v.iface.Addrs()
	if err != nil {
		log.Warnf("Failed to get interface addresses: %v", err)
		return net.IPv4zero
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4
			}
		}
	}

	return net.IPv4zero
}

func (v *VRRP) monitor() {
	ticker := time.NewTicker(3 * time.Duration(v.cfg.Vrrp.AdverInt) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			v.mu.Lock()
			if v.master {
				// Мы мастер, ничего не делаем
			} else {
				// Если давно не было advertisement, становимся мастером
				if time.Since(v.lastAdvert) > 3*time.Duration(v.cfg.Vrrp.AdverInt)*time.Second {
					log.Infof("No advertisements received, becoming master")
					v.becomeMaster()
				}
			}
			v.mu.Unlock()
		}
	}
}

func (v *VRRP) becomeMaster() {
	v.master = true
	v.announceVIP()
	log.Infof("Became VRRP master")
}

func (v *VRRP) becomeBackup() {
	v.master = false
	v.releaseVIP()
	log.Infof("Became VRRP backup")
}
