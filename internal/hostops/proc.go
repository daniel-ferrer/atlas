package hostops

import (
	"errors"
	"strconv"
	"strings"
)

func StatFlags(stat string) (uint64, error) {
	// comm may contain spaces and parentheses. Field 9 is flags; the first
	// field after the last ')' is field 3 (state).
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 7 {
		return 0, errors.New("invalid process stat")
	}
	return strconv.ParseUint(fields[6], 10, 64)
}
