package cli

import "github.com/alexflint/go-arg"

var SenderArgs struct {
	Dev string `arg:"positional,required"`
	IP string `arg:"positional,required"`
	Src int `arg:"-s" default:"862"`
	Dest int `arg:"-d" default:"862"`
	Count uint32 `arg:"-c,--" default:"0"`
	Interval uint32 `arg:"-i,--" default:"1000"`
}

func ParseSenderArgs() error {
	arg.MustParse(&SenderArgs)
	return nil
}

var ReflectorArgs struct {
	Dev string `arg:"positional,required"`
	Src int `arg:"-s" default:"862"`
}

func ParseReflectorArgs() error {
	arg.MustParse(&SenderArgs)
	return nil
}
