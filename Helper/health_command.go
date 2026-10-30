package main

import "regexp"

var healthCheckPattern = regexp.MustCompile(`^check ([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\n$`)

func healthCheckCommand(command string) (string, bool) {
	match := healthCheckPattern.FindStringSubmatch(command)
	if len(match) != 2 {
		return "", false
	}
	return match[1], true
}
