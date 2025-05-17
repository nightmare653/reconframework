package utils

import (
	"net/url"
	"os"
	"strings"
)

func JoinLines(lines []string) string {
	return strings.Join(lines, "\n")
}

func ExtractHostnamesFromURLs(inputFile, outputFile string) error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	hostSet := make(map[string]struct{})
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		u, err := url.Parse(strings.Fields(line)[0])
		if err == nil && u.Host != "" {
			hostSet[u.Host] = struct{}{}
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}

	return os.WriteFile(outputFile, []byte(strings.Join(hosts, "\n")), 0644)
}
