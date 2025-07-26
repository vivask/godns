// godns/internal/server/vrrp/vip.go
package vrrp

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"

	"godns/internal/log"
)

// announceVIP добавляет VIP на интерфейс
func (v *VRRP) announceVIP() error {
	if runtime.GOOS != "linux" {
		log.Warn("VIP management only supported on Linux")
		return nil
	}

	// Проверяем, назначен ли уже VIP
	if v.isVIPAddressAssigned() {
		return nil
	}

	// Добавляем VIP на интерфейс
	cmd := exec.Command("ip", "addr", "add", v.vip.String()+"/32", "dev", v.iface.Name)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Errorf("Failed to add VIP: %s, output: %s", err, string(output))
		return fmt.Errorf("failed to add VIP: %w", err)
	}

	// Добавляем маршрут для VIP
	cmd = exec.Command("ip", "route", "add", v.vip.String()+"/32", "dev", v.iface.Name)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Warnf("Failed to add route for VIP: %s, output: %s", err, string(output))
		// Не возвращаем ошибку, так как VIP уже назначен
	}

	log.Infof("VIP %s assigned to interface %s", v.vip.String(), v.iface.Name)
	return nil
}

// releaseVIP удаляет VIP с интерфейса
func (v *VRRP) releaseVIP() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// Удаляем VIP с интерфейса
	cmd := exec.Command("ip", "addr", "del", v.vip.String()+"/32", "dev", v.iface.Name)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Warnf("Failed to remove VIP: %s, output: %s", err, string(output))
		// Не возвращаем ошибку, так как это часть остановки
	}

	log.Infof("VIP %s released from interface %s", v.vip.String(), v.iface.Name)
	return nil
}

// isVIPAddressAssigned проверяет, назначен ли VIP на интерфейс
func (v *VRRP) isVIPAddressAssigned() bool {
	addrs, err := v.iface.Addrs()
	if err != nil {
		log.Warnf("Failed to get interface addresses: %v", err)
		return false
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.Equal(v.vip) {
				return true
			}
		}
	}

	return false
}

// GetVirtualIP возвращает текущий виртуальный IP
func (v *VRRP) GetVirtualIP() net.IP {
	return v.vip
}

// GetInterfaceName возвращает имя интерфейса
func (v *VRRP) GetInterfaceName() string {
	return v.iface.Name
}

// isActive проверяет, активен ли VRRP (мастер или backup)
func (v *VRRP) isActive() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.master || !v.lastAdvert.IsZero()
}
