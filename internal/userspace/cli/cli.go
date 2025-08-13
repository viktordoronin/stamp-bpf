package cli

import "github.com/alexflint/go-arg"

type SenderArgs struct {
	Dev string `arg:"positional,required"`
	IP string `arg:"positional,required"`
	Src int `arg:"-s" default:"862"`
	Dest int `arg:"-d" default:"862"`
	Count uint32 `arg:"-c,--" default:"0"`
	Interval uint32 `arg:"-i,--" default:"1000"`
}

func ParseSenderArgs() SenderArgs {
	var args SenderArgs
	arg.MustParse(&args)
	return args
}

type ReflectorArgs struct {
	Dev string `arg:"positional,required"`
	Src int `arg:"-s" default:"862"`
}

func ParseReflectorArgs() ReflectorArgs {
	var args ReflectorArgs
	arg.MustParse(&args)
	return args
}
