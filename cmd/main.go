package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kptm-tools/owasp-cli/internal/api"
	"github.com/kptm-tools/owasp-cli/internal/config"
	"github.com/kptm-tools/owasp-cli/internal/dto"
	"github.com/urfave/cli/v3"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	c := config.LoadConfig()
	zapClient := api.NewZapClient(c.Server.URL)
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
				Value:    "",
				Usage:    "Path with the file name where is going to be saved the result",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "timeout",
				Value:    "",
				Usage:    "Time duration to be canceled",
				Required: false,
			},
		},
		Before: func(ctx context.Context, command *cli.Command) (context.Context, error) {
			var timeout time.Duration
			timeout = getTimeout(c, command)
			// Create deadline for the shutdown of scan
			ctxDeadline, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			return ctxDeadline, nil
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			result := zapClient.HandleScan(cmd.String("target"))
			fmt.Println(cmd.String("output"))
			var scanResponse *dto.JsonResult
			if err := json.NewDecoder(bytes.NewReader(result)).Decode(&scanResponse); err != nil {
				fmt.Println("error parsing to json", err)
			}

			switch len(cmd.String("output")) {
			case 0: // print json
				{
					scanJson, _ := json.MarshalIndent(scanResponse, "", "\t")
					fmt.Println(string(scanJson))
					break
				}
			default: // write to file
				file, errFile := os.OpenFile(cmd.String("output"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
				if errFile != nil {
					fmt.Println(errFile)
				}
				defer file.Close()
				encoder := json.NewEncoder(file)
				errEncoding := encoder.Encode(scanResponse)
				if errEncoding != nil {
					fmt.Println(errEncoding)
				}
			}
			return nil
		},
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

func getTimeout(c *config.Config, cmd *cli.Command) time.Duration {
	var timeout int
	switch len(cmd.String("timeout")) {
	case 0:
		timeout, _ = strconv.Atoi(c.Timeout)
	default:
		timeout, _ = strconv.Atoi(cmd.String("timeout"))
	}
	return time.Duration(timeout) * time.Second
}
