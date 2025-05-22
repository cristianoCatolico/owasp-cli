package main

import (
	"context"
	"fmt"
	"github.com/kptm-tools/owasp-cli/internal/api"
	"github.com/urfave/cli/v3"
	"log"
	"os"
)

func main() {

	cmd := &cli.Command{
		Name:      "owasp zap cli",
		Version:   "v1.0.0",
		Copyright: "(c) 1999 Serious Enterprise",
		Usage:     "This tool connects to owasp zap server to do specific requests",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "target",
				Value:    "",
				Usage:    "Url to be scanned in zap",
				Required: true,
				Action:   validateActionTarget,
			},
			&cli.StringFlag{
				Name:     "output",
				Value:    "result",
				Usage:    "Path with the file name where is going to be saved the result",
				Required: false,
			},
		},
		Action: handleAction,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func validateActionTarget(ctx context.Context, cmd *cli.Command, value string) error {
	if len(value) == 0 {
		return fmt.Errorf("flag target value %v must be a URL", value)
	}
	return nil
}

func handleAction(ctx context.Context, cmd *cli.Command) error {

	api.NewZapServer(cmd.String("target"), cmd)
	return nil
}
