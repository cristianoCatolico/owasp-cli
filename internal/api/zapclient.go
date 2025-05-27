package api

import (
	"fmt"
	"github.com/zaproxy/zap-api-go/zap"
	"log"
	"strconv"
	"time"
)

type CliResult struct {
	zap.Interface
}

func NewZapClient(url string) *CliResult {
	cfg := &zap.Config{
		Proxy: url,
	}
	client, err := zap.NewClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	//_, err = client.Script().Load("LogMessages.js", "httpsender", "Oracle Nashorn", "/zap/wrk/LogMessages.js", "", "")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//_, err = client.Script().Enable("LogMessages.js")
	//if err != nil {
	//	log.Fatal(err)
	//}
	cliResult := &CliResult{
		Interface: client,
	}
	return cliResult
}

func (client *CliResult) HandleScan(target string) []byte {
	// Start spidering the target
	fmt.Println("Spider : " + target)
	resp, err := client.Spider().Scan(target, "", "", "", "")
	if err != nil {
		log.Fatal(err)
	}
	// The scan now returns a scan id to support concurrent scanning
	scanid := resp["scan"].(string)
	for {
		time.Sleep(1000 * time.Millisecond)
		responseStatus, errStatus := client.Spider().Status(scanid)
		if errStatus != nil {
			log.Fatal(err)
		}
		status := responseStatus["status"]
		if status == nil {
			break
		}
		progress, _ := strconv.Atoi(status.(string))
		if progress >= 100 {
			break
		}
	}
	fmt.Println("Spider complete")

	// Give the passive scanner a chance to complete
	time.Sleep(2000 * time.Millisecond)

	fmt.Println("Active scan : " + target)
	resp, err = client.Ascan().Scan(target, "True", "False", "", "", "", "")
	if err != nil {
		log.Fatal(err)
	}
	// The scan now returns a scan id to support concurrent scanning
	scanid = resp["scan"].(string)
	for {
		time.Sleep(5000 * time.Millisecond)
		resp, _ = client.Ascan().Status(scanid)
		progress, _ := strconv.Atoi(resp["status"].(string))
		fmt.Printf("Active Scan progress : %d\n", progress)
		if progress >= 100 {
			break
		}
	}
	fmt.Println("Active Scan complete")
	report, err := client.Core().Jsonreport()
	if err != nil {
		log.Fatal(err)
	}
	return report
}
