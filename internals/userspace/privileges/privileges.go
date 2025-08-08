package privileges

import(
	"os/user"
	"kernel.org/pub/linux/libs/security/libcap/cap"
	"fmt"
	"errors"
)

var errCaps = errors.New("You don't have the linux capabilities required")
var errRoot = errors.New("You don't have the superuser privileges")

// This function checks if we got necessary caps for running this without root
// returns nil if OK
// TODO: accept port number as arg to see if we need to check for CAP_NET_BIND_SERVICE
func checkCaps() error {
	got:=cap.GetProc()
	want,err:=cap.FromText("cap_net_bind_service,cap_net_admin,cap_bpf=ep")
	if err!=nil{
		return fmt.Errorf("Error generating required capabilities set: %w",err)
	}
	diff,err:=got.Cf(want)
	if err!=nil{
		return fmt.Errorf("Error diffing caps: %w",err)
	}
	if diff!=0 {
		return errCaps
	}
	return nil
}

// This checks if we have root
func checkSu() error {
	usr,err:=user.Current()
	if err!=nil{
		return fmt.Errorf("Error getting uid: %w",err)
	}
	if usr.Uid!="0" {
		return errRoot
	}
	return nil
}

// User-facing function, fails if both checks fail
func Check() error {
	err1:=checkCaps()
	err2:=checkSu()
	if err1!=nil && err2!=nil {
		return fmt.Errorf("Privilege check failed, errors: %w; %w",err1,err2)
	}
	return nil
}
