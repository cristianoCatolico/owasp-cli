package utils

import (
	"github.com/kptm-tools/owasp-cli/internal/customerrors"
	probing "github.com/prometheus-community/pro-bing"
	"log/slog"
	"strings"
	"time"
)

func ValidateHost(host string) error {
	normalizedHost := NormalizeURL(host)
	addr := strings.Split(normalizedHost, "//")[1]
	pinger, err := probing.NewPinger(addr)
	if err != nil {
		slog.Error("Failed to probe host", slog.Any("error", err))
		return customerrors.ErrHostUnhealthy
	}
	pinger.Count = 1
	pinger.Timeout = 5 * time.Second
	err = pinger.Run()
	defer pinger.Stop()
	if err != nil {
		return err
	}
	stats := pinger.Statistics()
	if stats.PacketLoss == 100 {
		slog.Error("Failed to ping host", slog.String("address", stats.IPAddr.String()))
		return customerrors.ErrHostUnhealthy
	}
	slog.Debug("Pinger stats", slog.Any("stats", pinger.Statistics()))
	return nil
}

// NormalizeURL prefixes the protocol if it's missing in the URL
func NormalizeURL(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	return url
}
