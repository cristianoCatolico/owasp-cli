package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kptm-tools/owasp-cli/internal/api"
	"github.com/kptm-tools/owasp-cli/internal/config"
	"github.com/kptm-tools/owasp-cli/internal/dto"
	"github.com/kptm-tools/owasp-cli/internal/utils"
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
			&cli.StringFlag{
				Name:     "user",
				Value:    "",
				Usage:    "Use together with password flag to provide credentials for authenticate to a site",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "password",
				Value:    "",
				Usage:    "Use together with user flag to provide credentials for authenticate to a site",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "type",
				Value:    "active",
				Usage:    "Use to specify if is a passive or active scan",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "strength",
				Value:    "low",
				Usage:    "Use to determine the number of attacks within scan",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "threshold",
				Value:    "low",
				Usage:    "Use to dictate how scan must be before reporting a vulnerability",
				Required: false,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			var timeout time.Duration
			timeout = getTimeout(c, cmd)
			ctxDeadline, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			credential := &dto.Credential{
				User:     cmd.String("user"),
				Password: cmd.String("password"),
			}
			if len(cmd.String("user")) == 0 || len(cmd.String("password")) == 0 {
				credential = nil
			}
			result, errHandle := zapClient.HandleScan(
				cmd.String("target"),
				cmd.String("type"),
				credential,
				cmd.String("strength"),
				cmd.String("threshold"),
				ctxDeadline)
			if errHandle != nil {
				fmt.Println(errHandle)
			}
			fmt.Println(string(result))
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
				break
			}
			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func validateActionTarget(ctx context.Context, cmd *cli.Command, value string) error {
	errValidation := utils.ValidateHost(value)
	if len(value) == 0 || errValidation != nil {
		return fmt.Errorf("flag target value %v must be a URL %w", value, errValidation)
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
