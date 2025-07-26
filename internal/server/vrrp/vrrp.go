// godns/internal/server/vrrp/vrrp.go
package vrrp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"godns/internal/config"
	"godns/internal/log"

	"github.com/mdlayher/packet"
)

const (
	VRRP_PROTO_NUM   = 112
	VRRP_VERSION     = 2
	VRRP_TYPE_ADVERT = 1
	VRRP_PRIO_OWNER  = 255
	VRRP_PRIO_DFL    = 100
	VRRP_PRIO_STOP   = 0

	// VRRP states
	STATE_INIT = iota
	STATE_BACKUP
	STATE_MASTER

	// VRRP events
	EVENT_START
	EVENT_SHUTDOWN
	EVENT_GOT_ADVERT
	EVENT_MASTER_DOWN
)

var (
	VRRPMultiAddrIPv4 = net.IPv4(224, 0, 0, 18)
	VRRPMultiMAC, _   = net.ParseMAC("01:00:5e:00:00:12")
	byteOrder         = binary.BigEndian
)

type VRRP struct {
	cfg        *config.Config
	iface      *net.Interface
	conn       *packet.Conn
	vip        net.IP
	state      int
	priority   uint
	vrid       uint
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	lastAdvert time.Time
	advertInt  int // Advertisement interval in seconds
}

type VRRPHeader struct {
	VersionType uint8
	VRID        uint8
	Priority    uint8
	CountIP     uint8
	AuthType    uint8
	AdverInt    uint8
	Checksum    uint16
	IPs         []net.IP
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
	// ETH_P_IP = 0x0800
	conn, err := packet.Listen(iface, packet.Raw, 0x0800, nil)
	if err != nil {
		// Fallback - прослушивать все пакеты
		conn, err = packet.Listen(iface, packet.Raw, 0, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create packet socket: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	v := &VRRP{
		cfg:       cfg,
		iface:     iface,
		conn:      conn,
		vip:       vip,
		state:     STATE_INIT,
		priority:  uint(cfg.Vrrp.Prior),
		vrid:      uint(cfg.Vrrp.Vrid),
		advertInt: cfg.Vrrp.AdverInt,
		ctx:       ctx,
		cancel:    cancel,
	}

	log.Infof("VRRP initialized: iface=%s, vrid=%d, priority=%d, vip=%s, advert_int=%d",
		iface.Name, v.vrid, v.priority, vip.String(), v.advertInt)

	return v, nil
}

func (v *VRRP) Start() error {
	if v == nil {
		return nil
	}

	log.Infof("VRRP starting on interface %s, VRID %d, priority %d",
		v.iface.Name, v.vrid, v.priority)

	// Начинаем как INIT
	v.state = STATE_INIT

	// Запуск goroutine для прослушивания VRRP пакетов
	go v.listen()

	// Запуск goroutine для отправки advertisement пакетов (если мастер)
	go v.advertise()

	// Запуск goroutine для проверки состояния
	go v.monitor()

	// Отправляем событие START
	v.handleEvent(EVENT_START)

	return nil
}

func (v *VRRP) Stop() error {
	if v == nil {
		return nil
	}

	log.Infof("Stopping VRRP on interface %s", v.iface.Name)

	v.cancel()
	if v.conn != nil {
		v.conn.Close()
	}

	// Отправляем shutdown advertisement если мы мастер
	if v.getState() == STATE_MASTER {
		log.Debugf("Sending shutdown advertisement")
		v.sendAdvertisement(VRRP_PRIO_STOP)
		v.releaseVIP()
	}

	log.Info("VRRP stopped")
	return nil
}

func (v *VRRP) getState() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.state
}

func (v *VRRP) setState(state int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	oldState := v.state
	v.state = state
	log.Infof("VRRP state changed: %d -> %d", oldState, state)
}

func (v *VRRP) handleEvent(event int) {
	switch event {
	case EVENT_START:
		v.setState(STATE_BACKUP)
		log.Infof("VRRP started in BACKUP state")
	case EVENT_SHUTDOWN:
		if v.getState() == STATE_MASTER {
			v.sendAdvertisement(VRRP_PRIO_STOP)
			v.releaseVIP()
		}
		v.setState(STATE_INIT)
	case EVENT_GOT_ADVERT:
		// Обрабатывается в processAdvertisement
	case EVENT_MASTER_DOWN:
		if v.getState() == STATE_BACKUP {
			v.becomeMaster()
		}
	}
}

func (v *VRRP) listen() {
	buf := make([]byte, 1500)
	log.Debugf("Starting VRRP packet listener on %s", v.iface.Name)

	for {
		select {
		case <-v.ctx.Done():
			log.Debugf("VRRP listener stopped")
			return
		default:
		}

		n, addr, err := v.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-v.ctx.Done():
				return
			default:
				log.Warnf("VRRP read error: %v", err)
				continue
			}
		}

		log.Debugf("Received %d bytes from %v", n, addr)

		if err := v.handlePacket(buf[:n]); err != nil {
			log.Debugf("VRRP packet handling error: %v", err)
		}
	}
}

func (v *VRRP) handlePacket(data []byte) error {
	log.Debugf("Handling incoming packet, size: %d bytes", len(data))

	// Минимальный размер IP заголовка
	if len(data) < 20 {
		log.Debugf("Packet too short to be IP: %d bytes", len(data))
		return nil
	}

	// Проверяем версию IP (первые 4 бита)
	version := data[0] >> 4
	if version != 4 {
		log.Debugf("Not an IPv4 packet, version: %d", version)
		return nil
	}

	// Проверяем протокол (должен быть VRRP)
	protocol := data[9]
	if protocol != VRRP_PROTO_NUM {
		log.Debugf("Not VRRP packet, protocol: %d", protocol)
		return nil
	}

	// Получаем длину заголовка IP
	ipHeaderLen := int(data[0]&0x0F) * 4
	log.Debugf("IP header length: %d bytes", ipHeaderLen)

	// Проверяем, что у нас достаточно данных для IP заголовка
	if len(data) < ipHeaderLen {
		log.Debugf("Packet too short for IP header: %d < %d", len(data), ipHeaderLen)
		return nil
	}

	// Извлекаем IP адреса источника и назначения
	if len(data) >= 20 {
		srcIP := net.IP(data[12:16])
		dstIP := net.IP(data[16:20])
		log.Debugf("IP packet: src=%s, dst=%s, protocol=%d", srcIP, dstIP, protocol)

		// Проверяем, что пакет отправлен на multicast адрес VRRP
		if !dstIP.Equal(VRRPMultiAddrIPv4) {
			log.Debugf("VRRP packet not for our multicast address: %s", dstIP)
			return nil
		}
	}

	// Извлекаем данные VRRP (после IP заголовка)
	if len(data) <= ipHeaderLen {
		log.Debugf("No VRRP data after IP header")
		return nil
	}

	vrrpData := data[ipHeaderLen:]
	log.Debugf("VRRP data size: %d bytes", len(vrrpData))

	// Парсим VRRP пакет
	vrrpHdr, err := v.parseVRRPPacket(vrrpData)
	if err != nil {
		log.Debugf("Failed to parse VRRP packet: %v", err)
		return nil
	}

	log.Debugf("Parsed VRRP packet: VRID=%d, Priority=%d, CountIP=%d, AdverInt=%d",
		vrrpHdr.VRID, vrrpHdr.Priority, vrrpHdr.CountIP, vrrpHdr.AdverInt)

	// Проверяем VRID
	if uint(vrrpHdr.VRID) != v.vrid {
		log.Debugf("VRID mismatch: received %d, expected %d", vrrpHdr.VRID, v.vrid)
		return nil
	}

	log.Debugf("VRID match, processing advertisement from priority %d", vrrpHdr.Priority)

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

	log.Debugf("VRRP header: Version=%d, Type=%d, VRID=%d, Priority=%d, CountIP=%d, AdverInt=%d",
		version, msgType, hdr.VRID, hdr.Priority, hdr.CountIP, hdr.AdverInt)

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
		log.Debugf("VRRP IP[%d]: %s", i, ip.String())
	}

	// Проверяем контрольную сумму
	if !v.verifyChecksum(data) {
		log.Debugf("Invalid VRRP checksum")
		return nil, fmt.Errorf("invalid VRRP checksum")
	}

	log.Debugf("VRRP checksum verified successfully")
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

	log.Debugf("Checksum verification: calculated=0x%04x, actual=0x%04x, match=%t",
		calculated, actual, calculated == actual)

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
	result := ^uint16(sum)
	log.Debugf("Calculated checksum: 0x%04x", result)
	return result
}

func (v *VRRP) processAdvertisement(hdr *VRRPHeader) {
	v.mu.Lock()
	// Сохраняем время получения advertisement
	v.lastAdvert = time.Now()
	v.mu.Unlock()

	log.Debugf("Processing advertisement: priority=%d, current state=%d", hdr.Priority, v.state)

	// Если приоритет 0 - другой узел выходит из строя
	if hdr.Priority == 0 {
		log.Infof("Received priority 0 advertisement (shutdown signal)")
		if v.state == STATE_BACKUP {
			log.Infof("Other master left, attempting to become master")
			v.becomeMaster()
		}
		return
	}

	// Если мы мастер и получили advertisement с более высоким или равным приоритетом
	if v.state == STATE_MASTER {
		log.Debugf("We are master, checking received priority %d vs our priority %d",
			hdr.Priority, v.priority)

		if uint(hdr.Priority) > v.priority {
			log.Infof("Higher priority node detected (%d > %d), becoming backup",
				hdr.Priority, v.priority)
			v.becomeBackup()
		} else if uint(hdr.Priority) == v.priority && len(hdr.IPs) > 0 {
			// При равных приоритетах сравниваем IP адреса
			srcIP := v.getInterfaceIP()
			if hdr.IPs[0].String() > srcIP.String() {
				log.Infof("Equal priority, higher IP detected, becoming backup")
				v.becomeBackup()
			}
		}
	} else if v.state == STATE_BACKUP {
		// Мы backup, проверяем приоритет
		log.Debugf("We are backup, received advertisement from priority %d", hdr.Priority)

		if uint(hdr.Priority) > v.priority {
			log.Debugf("Higher priority node detected, staying backup")
			// Просто обновляем время, остаемся backup
		} else if uint(hdr.Priority) == v.priority {
			// При равных приоритетах сравниваем IP адреса
			srcIP := v.getInterfaceIP()
			if hdr.IPs[0].String() > srcIP.String() {
				log.Debugf("Equal priority, higher IP detected, staying backup")
				// Просто обновляем время, остаемся backup
			} else {
				// Наш IP больше, становимся мастером
				log.Infof("Equal priority, our IP is higher, becoming master")
				v.becomeMaster()
			}
		} else {
			// Приоритет входящего пакета меньше нашего
			log.Infof("Lower priority node detected (%d < %d), becoming master",
				hdr.Priority, v.priority)
			v.becomeMaster()
		}
	}
	// Если состояние INIT, игнорируем
}

func (v *VRRP) advertise() {
	log.Debugf("Starting advertisement routine")

	ticker := time.NewTicker(time.Duration(v.advertInt) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			log.Debugf("Advertisement routine stopped")
			return
		case <-ticker.C:
			if v.getState() == STATE_MASTER {
				log.Debugf("Sending advertisement with priority %d", v.priority)
				if err := v.sendAdvertisement(uint8(v.priority)); err != nil {
					log.Warnf("Failed to send advertisement: %v", err)
				}
			} else {
				log.Debugf("Not master, skipping advertisement")
			}
		}
	}
}

func (v *VRRP) sendAdvertisement(priority uint8) error {
	log.Debugf("Preparing VRRP advertisement: priority=%d, VRID=%d", priority, v.vrid)

	// Создаем VRRP пакет
	vrrpData := make([]byte, 12) // 8 байт заголовка + 4 байта VIP
	vrrpData[0] = (VRRP_VERSION << 4) | VRRP_TYPE_ADVERT
	vrrpData[1] = uint8(v.vrid)
	vrrpData[2] = priority
	vrrpData[3] = 1                  // CountIP
	vrrpData[4] = 0                  // AuthType - none
	vrrpData[5] = uint8(v.advertInt) // AdverInt

	// IP адреса
	copy(vrrpData[8:12], v.vip.To4())
	log.Debugf("VRRP data prepared: %x", vrrpData)

	// Вычисляем контрольную сумму
	checksum := v.calculateChecksum(vrrpData)
	vrrpData[6] = byte(checksum >> 8)
	vrrpData[7] = byte(checksum & 0xFF)
	log.Debugf("VRRP checksum set: 0x%02x%02x", vrrpData[6], vrrpData[7])

	// Создаем минимальный IP заголовок
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, IHL 5
	ipHeader[1] = 0x00 // TOS
	// Length (20 + 12 = 32 bytes)
	ipHeader[2] = 0x00
	ipHeader[3] = 0x20
	ipHeader[4] = 0x00 // ID
	ipHeader[5] = 0x00
	ipHeader[6] = 0x40                 // Flags (Don't Fragment)
	ipHeader[7] = 0x00                 // Fragment Offset
	ipHeader[8] = 0xFF                 // TTL (должен быть 255 для VRRP)
	ipHeader[9] = byte(VRRP_PROTO_NUM) // Protocol
	// Checksum будет вычислен позже
	ipHeader[10] = 0x00
	ipHeader[11] = 0x00
	// Src IP - используем первый IP интерфейса
	srcIP := v.getInterfaceIP()
	copy(ipHeader[12:16], srcIP.To4())
	log.Debugf("Source IP: %s", srcIP.String())
	// Dst IP - VRRP multicast 224.0.0.18
	copy(ipHeader[16:20], VRRPMultiAddrIPv4.To4())
	log.Debugf("Destination IP: %s", VRRPMultiAddrIPv4.String())

	// Вычисляем IP checksum
	ipChecksum := v.calculateIPChecksum(ipHeader[:20])
	ipHeader[10] = byte(ipChecksum >> 8)
	ipHeader[11] = byte(ipChecksum & 0xFF)
	log.Debugf("IP checksum: 0x%02x%02x", ipHeader[10], ipHeader[11])

	// Собираем полный пакет
	packetData := make([]byte, len(ipHeader)+len(vrrpData))
	copy(packetData, ipHeader)
	copy(packetData[20:], vrrpData)
	log.Debugf("Full packet size: %d bytes", len(packetData))

	// Отправляем пакет
	dstAddr := &packet.Addr{
		HardwareAddr: VRRPMultiMAC, // VRRP multicast MAC
	}

	log.Debugf("Sending VRRP packet to multicast MAC: %s", VRRPMultiMAC.String())
	_, err := v.conn.WriteTo(packetData, dstAddr)
	if err != nil {
		log.Warnf("Failed to send VRRP packet: %v", err)
		return fmt.Errorf("failed to send VRRP packet: %w", err)
	}

	log.Debugf("VRRP advertisement sent successfully")
	return nil
}

func (v *VRRP) calculateIPChecksum(header []byte) uint16 {
	// Копируем заголовок и обнуляем поле checksum
	checksumHeader := make([]byte, len(header))
	copy(checksumHeader, header)
	checksumHeader[10] = 0
	checksumHeader[11] = 0

	var sum uint32
	for i := 0; i < len(checksumHeader); i += 2 {
		sum += uint32(checksumHeader[i])<<8 | uint32(checksumHeader[i+1])
	}

	// Складываем переносы
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Инвертируем результат
	result := ^uint16(sum)
	log.Debugf("Calculated IP checksum: 0x%04x", result)
	return result
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
				log.Debugf("Interface IP found: %s", ip4.String())
				return ip4
			}
		}
	}

	log.Debugf("No valid interface IP found, using 0.0.0.0")
	return net.IPv4zero
}

func (v *VRRP) monitor() {
	log.Debugf("Starting VRRP monitor")

	// Таймер мастер-даун = 3 * advert_int
	masterDownInterval := 3 * time.Duration(v.advertInt) * time.Second
	ticker := time.NewTicker(time.Second) // Проверяем каждую секунду
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			log.Debugf("Monitor stopped")
			return
		case <-ticker.C:
			if v.getState() == STATE_MASTER {
				log.Debugf("Monitor: we are master, no action needed")
				// Мы мастер, ничего не делаем
			} else if v.getState() == STATE_BACKUP {
				// Проверяем, не истекло ли время с последнего advertisement
				v.mu.RLock()
				lastAdvert := v.lastAdvert
				v.mu.RUnlock()

				// Если это первый запуск и lastAdvert нулевой, пропускаем
				if lastAdvert.IsZero() {
					log.Debugf("Monitor: backup state, no advertisements yet")
					continue
				}

				if time.Since(lastAdvert) > masterDownInterval {
					log.Infof("Master down detected (no advertisements for %v), becoming master",
						time.Since(lastAdvert))
					v.handleEvent(EVENT_MASTER_DOWN)
				} else {
					log.Debugf("Monitor: backup state, last advert %v ago",
						time.Since(lastAdvert))
				}
			}
		}
	}
}

func (v *VRRP) becomeMaster() {
	log.Infof("Becoming VRRP master")
	v.setState(STATE_MASTER)
	v.announceVIP()
	log.Infof("Became VRRP master")
}

func (v *VRRP) becomeBackup() {
	log.Infof("Becoming VRRP backup")
	v.setState(STATE_BACKUP)
	v.releaseVIP()
	log.Infof("Became VRRP backup")
}
