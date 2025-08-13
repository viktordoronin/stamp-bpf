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
func checkCaps(port int) error {
	got:=cap.GetProc()
	var err error
	var want *cap.Set
	// if it's not a well-known port we don't need bind cap
	if port<1023 {
		want,err=cap.FromText("cap_net_bind_service,cap_net_admin,cap_bpf=ep")
	}	else {
		want,err=cap.FromText("cap_net_admin,cap_bpf=ep")
	}
	if err!=nil{
		return fmt.Errorf("Error generating required capabilities set: %w",err)
	}
	// if it's zero we cool
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
func Check(port int) error {
	err1:=checkCaps(port)
	err2:=checkSu()
	if err1!=nil && err2!=nil {
		return fmt.Errorf("Privilege check failed, errors: \n%w \n%w\n(you need either, not both)",err1,err2)
	}
	return nil
}
