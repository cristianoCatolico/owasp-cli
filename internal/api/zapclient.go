package api

import (
	"context"
	"fmt"
	"github.com/kptm-tools/owasp-cli/internal/dto"
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

func (client *CliResult) HandleScan(target string, typeScan string, credential *dto.Credential, ctx context.Context) ([]byte, error) {

	var (
		result []byte
		err    error
		done   = make(chan struct{})
	)

	go func() {
		switch typeScan {
		case "passive":
			result, err = client.passiveScan(target, credential)
		default:
			result, err = client.activeScan(target, credential)
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("cancelled by timeout")
	case <-done:
		return result, err
	}
}

func (client *CliResult) activeScan(target string, credential *dto.Credential) ([]byte, error) {
	if credential == nil {
		resp, err := client.Spider().Scan(target, "", "", "", "")
		if err != nil {
			log.Fatal(err)
		}
		// The scan now returns a scan id to support concurrent scanning
		scanId := resp["scan"].(string)
		client.monitorStatus(scanId, true)
		fmt.Println("Spider complete")

		// Give the passive scanner a chance to complete
		time.Sleep(2000 * time.Millisecond)

		fmt.Println("Active scan : " + target)
		resp, err = client.Ascan().Scan(target, "True", "False", "", "", "", "")
		if err != nil {
			log.Fatal(err)
		}
		// The scan now returns a scan id to support concurrent scanning
		scanId = resp["scan"].(string)
		client.monitorStatus(scanId, false)
		fmt.Println("Active Scan complete")
		report, err := client.Core().Jsonreport()
		if err != nil {
			log.Fatal(err)
		}
		return report, nil
	}
	contextName := "active-context"
	// 1. Create context
	respContext, err := client.Context().NewContext(contextName)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(respContext)
	contextID := respContext["contextId"].(string)

	// 2. Include target in context
	includeRegex := target + ".*"
	respInclude, err := client.Context().IncludeInContext("active-context", includeRegex)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(respInclude)

	// 3. Set authentication method (example: form-based)
	_, err = client.Authentication().SetAuthenticationMethod(
		contextID,
		"formBasedAuthentication",
		"loginUrl="+target,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 4. Add user with credentials
	userResp, err := client.Users().NewUser(contextID, "testuser")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(userResp)
	userID := userResp["userId"].(string)

	_, err = client.Users().SetAuthenticationCredentials(
		contextID,
		userID,
		"username="+credential.User+"&password="+credential.Password,
	)
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.Users().SetUserEnabled(contextID, userID, "True")
	if err != nil {
		log.Fatal(err)
	}

	// 5. Spider as user
	spiderResp, err := client.Spider().ScanAsUser(target, contextID, userID, "", "true", "")
	if err != nil {
		log.Fatal(err)
	}
	spiderId := spiderResp["scan"].(string)
	client.monitorStatus(spiderId, true)
	fmt.Println("Spider as user complete")

	// 6. Start active scan as user
	scanResp, err := client.Ascan().ScanAsUser(target, contextID, userID, "True", "", "", "")
	if err != nil {
		log.Fatal(err)
	}
	scanID := scanResp["scan"].(string)
	// 7. Monitor status of scan
	client.monitorStatus(scanID, false)
	fmt.Println("Active Scan complete")

	// 8. Generate report
	report, err := client.Core().Jsonreport()
	if err != nil {
		log.Fatal(err)
	}

	// 9. Remove context (cleanup)
	respRemove, errRemoveContext := client.Context().RemoveContext(contextName)
	if errRemoveContext != nil {
		return nil, errRemoveContext
	}
	fmt.Println(respRemove)

	return report, nil
}

func (client *CliResult) monitorStatus(scanId string, isSpider bool) {
	for {
		time.Sleep(1000 * time.Millisecond)
		var responseStatus map[string]interface{}
		var errStatus error
		switch isSpider {
		case true:
			responseStatus, errStatus = client.Spider().Status(scanId)
		case false:
			responseStatus, errStatus = client.Ascan().Status(scanId)
		}

		if errStatus != nil {
			log.Fatal(errStatus)
		}
		status := responseStatus["status"]
		if status == nil {
			break
		}
		progress, _ := strconv.Atoi(status.(string))
		if progress >= 100 {
			break
		}
		fmt.Println("Monitor status:", progress)
	}
}

func (client *CliResult) passiveScan(target string, credential *dto.Credential) ([]byte, error) {
	if credential == nil {
		fmt.Println("Spider : " + target)
		resp, err := client.Spider().Scan(target, "", "True", "", "")
		if err != nil {
			log.Fatal(err)
		}
		scanSpiderId := resp["scan"].(string)
		client.monitorStatus(scanSpiderId, true)
		fmt.Println("Spider complete")

		// Wait for passive scan to finish
		for {
			time.Sleep(2 * time.Second)
			pscanStatus, err := client.Pscan().RecordsToScan()
			if err != nil {
				log.Fatal(err)
			}
			records, _ := strconv.Atoi(pscanStatus["recordsToScan"].(string))
			fmt.Printf("Passive Scan records left: %d\n", records)
			if records == 0 {
				break
			}
		}
		fmt.Println("Passive Scan complete")

		report, err := client.Core().Jsonreport()
		if err != nil {
			log.Fatal(err)
		}
		return report, nil
	}

	contextName := "passive-context"
	// 1. Create context
	respContext, err := client.Context().NewContext(contextName)
	if err != nil {
		log.Fatal(err)
	}
	contextID := respContext["contextId"].(string)

	// 2. Include target in context
	includeRegex := target + ".*"
	_, err = client.Context().IncludeInContext(contextName, includeRegex)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Set authentication method (example: form-based)
	_, err = client.Authentication().SetAuthenticationMethod(
		contextID,
		"formBasedAuthentication",
		"loginUrl="+target,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 4. Add user with credentials
	userResp, err := client.Users().NewUser(contextID, "testuser")
	if err != nil {
		log.Fatal(err)
	}
	userID := userResp["userId"].(string)

	_, err = client.Users().SetAuthenticationCredentials(
		contextID,
		userID,
		"username="+credential.User+"&password="+credential.Password,
	)
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.Users().SetUserEnabled(contextID, userID, "True")
	if err != nil {
		log.Fatal(err)
	}

	// 5. Spider as user
	spiderResp, err := client.Spider().ScanAsUser(target, contextID, userID, "", "True", "")
	if err != nil {
		log.Fatal(err)
	}
	spiderId := spiderResp["scan"].(string)
	client.monitorStatus(spiderId, true)
	fmt.Println("Spider as user complete")

	// 6. Wait for passive scan to finish
	for {
		time.Sleep(2 * time.Second)
		pscanStatus, err := client.Pscan().RecordsToScan()
		if err != nil {
			log.Fatal(err)
		}
		records, _ := strconv.Atoi(pscanStatus["recordsToScan"].(string))
		fmt.Printf("Passive Scan records left: %d\n", records)
		if records == 0 {
			break
		}
	}
	fmt.Println("Passive Scan complete")

	// 7. Generate report
	report, err := client.Core().Jsonreport()
	if err != nil {
		log.Fatal(err)
	}
	respRemove, errRemoveContext := client.Context().RemoveContext(contextID)
	if errRemoveContext != nil {
		return nil, errRemoveContext
	}
	fmt.Println(respRemove)
	return report, nil
}
