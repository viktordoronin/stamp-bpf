package loader

import (
	"fmt"
	"log"

	"golang.org/x/sys/unix"
)

// returns true if we need to add leap seconds to TAI clock
func checkTAI() bool {
	var tai, utc unix.Timespec
	unix.ClockGettime(unix.CLOCK_TAI, &tai)
	unix.ClockGettime(unix.CLOCK_REALTIME, &utc)
	if tai.Sec == utc.Sec {
		fmt.Println("TAI is equal to UTC - STAMP will account for that but you might wanna fix it on your system\n")
		return true
	} else if (tai.Sec-utc.Sec) > 36 && (tai.Sec-utc.Sec) < 38 {
		fmt.Println("TAI seems to be correctly offset from UTC, no correction required\n")
		return false
	} else {
		log.Fatalf("System error: irregular TAI-UTC offset")
		return false
	}
}
