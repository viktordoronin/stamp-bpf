package loader

import (
	"fmt"
	"log"
	"os/exec"

	"golang.org/x/sys/unix"
)

// returns true if we need to add leap seconds to TAI clock
func checkTAI() bool {
	var tai, utc unix.Timespec
	unix.ClockGettime(unix.CLOCK_TAI, &tai)
	unix.ClockGettime(unix.CLOCK_REALTIME, &utc)
	if tai.Sec == utc.Sec {
		fmt.Println("TAI is equal to UTC - STAMP will account for that but you might wanna fix it on your system")
		return true
	} else if (tai.Sec-utc.Sec) > 36 && (tai.Sec-utc.Sec) < 38 {
		fmt.Println("TAI seems to be correctly offset from UTC, no correction required")
		return false
	} else {
		log.Fatalf("System error: irregular (not 37) TAI-UTC offset")
		return false
	}
}

func checkSync() bool {
	var t unix.Timex
	t.Modes = unix.ADJ_OFFSET_SS_READ
	s, err := unix.Adjtimex(&t)
	if err != nil {
		log.Fatalf("Error getting adjtimex():", err)
		return false
	}
	if s == unix.TIME_ERROR {
		fmt.Println("System clock doesn't seem to be synced - you might wanna do that")
		return false
	} else {
		fmt.Println("System clock sync detected")
		return true
	}
}

func checkPTP() bool {
	cmd := exec.Command("bash", "-c", "journalctl | tail -n100 | grep ptp4l")
	err := cmd.Run()
	if err == nil {
		fmt.Println("Detected PTP syncing")
		return true
		// } else if err.(*exec.ExitError).ExitCode()==1 { // this doesn't account for non-systemd systems
	} else {
		fmt.Println("No PTP syncing detected(or the method might have failed)")
		return false
	}
}
