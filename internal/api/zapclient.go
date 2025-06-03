package api

import (
	"context"
	"fmt"
	"github.com/kptm-tools/owasp-cli/internal/dto"
	"github.com/zaproxy/zap-api-go/zap"
	"log"
	"strconv"
	"strings"
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
	cliResult := &CliResult{
		Interface: client,
	}
	return cliResult
}

func (client *CliResult) HandleScan(target string, typeScan string, credential *dto.Credential, strength string, threshold string, ctx context.Context) ([]byte, error) {
	switch typeScan {
	case "passive":
		return client.passiveScan(target, credential, ctx)
	default:
		return client.activeScan(target, credential, strength, threshold, ctx)
	}
}

func (client *CliResult) ListScannerIDs(policyName string) error {

	scanners, err := client.Ascan().Scanners(policyName, "")
	if err != nil {
		return err
	}
	for _, scanner := range scanners["scanners"].([]interface{}) {
		scannerMap := scanner.(map[string]interface{})
		fmt.Printf("ID: %s, Name: %s, Policy: %s\n",
			scannerMap["id"], scannerMap["name"], scannerMap["policyId"])
	}
	return nil
}

func (client *CliResult) activeScan(target string, credential *dto.Credential, strength string, threshold string, ctx context.Context) ([]byte, error) {
	// Set strength and threshold for all scanners in a policy
	policyName := "Default Policy" // or your custom policy name
	if len(strength) > 0 {
		// Set strength (e.g., "LOW", "MEDIUM", "HIGH", "INSANE")
		_, errStrength := client.Ascan().SetPolicyAttackStrength("0", strings.ToUpper(strength), policyName)
		if errStrength != nil {
			log.Fatal(errStrength)
		}
	}
	if len(threshold) > 0 {
		// Set threshold (e.g., "OFF", "LOW", "MEDIUM", "HIGH")
		_, errThreshold := client.Ascan().SetPolicyAlertThreshold("0", strings.ToUpper(threshold), policyName)
		if errThreshold != nil {
			log.Fatal(errThreshold)
		}
	}

	var (
		result       []byte
		scanId       string
		scanSpiderId string
		contextName  string
		errFunc      error
		done         = make(chan struct{})
	)
	go func() {
		if credential == nil {
			resp, errSpider := client.Spider().Scan(target, "", "", "", "")
			if errSpider != nil {
				result, errFunc = nil, errSpider
				close(done)
			}
			// The scan now returns a scan id to support concurrent scanning
			scanSpiderId = resp["scan"].(string)
			client.monitorStatus(scanSpiderId, true)
			fmt.Println("Spider complete")

			// Give the passive scanner a chance to complete
			time.Sleep(2000 * time.Millisecond)

			fmt.Println("Active scan : " + target)
			resp, errScan := client.Ascan().Scan(target, "True", "False", "", "", "", "")
			if errScan != nil {
				result, errFunc = nil, errScan
				close(done)
			}
			// The scan now returns a scan id to support concurrent scanning
			scanId = resp["scan"].(string)
			client.monitorStatus(scanId, false)
			fmt.Println("Active Scan complete")
			report, errReport := client.Core().Jsonreport()
			if errReport != nil {
				result, errFunc = nil, errReport
				close(done)
			}
			result, errFunc = report, nil
			close(done)
		}
		contextName = "active-context"
		// 1. Create context
		respContext, errNewContext := client.Context().NewContext(contextName)
		if errNewContext != nil {
			result, errFunc = nil, errNewContext
			close(done)
		}
		fmt.Println(respContext)
		contextID := respContext["contextId"].(string)

		// 2. Include target in context
		includeRegex := target + ".*"
		_, errIncludeContext := client.Context().IncludeInContext("active-context", includeRegex)
		if errIncludeContext != nil {
			result, errFunc = nil, errIncludeContext
			close(done)
		}

		// 3. Set authentication method (example: form-based)
		_, errAuthMethod := client.Authentication().SetAuthenticationMethod(
			contextID,
			"formBasedAuthentication",
			"loginUrl="+target,
		)
		if errAuthMethod != nil {
			result, errFunc = nil, errAuthMethod
			close(done)
		}

		// 4. Add user with credentials
		userResp, errNewUser := client.Users().NewUser(contextID, "testuser")
		if errNewUser != nil {
			result, errFunc = nil, errNewUser
			close(done)
		}
		userID := userResp["userId"].(string)

		_, errAuthCredential := client.Users().SetAuthenticationCredentials(
			contextID,
			userID,
			"username="+credential.User+"&password="+credential.Password,
		)
		if errAuthCredential != nil {
			result, errFunc = nil, errAuthCredential
			close(done)
		}

		_, errUserEnabled := client.Users().SetUserEnabled(contextID, userID, "True")
		if errUserEnabled != nil {
			result, errFunc = nil, errUserEnabled
			close(done)
		}

		// 5. Spider as user
		spiderResp, errSpider := client.Spider().ScanAsUser(target, contextID, userID, "", "true", "")
		if errSpider != nil {
			result, errFunc = nil, errSpider
			close(done)
		}
		scanSpiderId = spiderResp["scan"].(string)
		client.monitorStatus(scanSpiderId, true)
		fmt.Println("Spider as user complete")

		// 6. Start active scan as user
		scanResp, errScanAsUser := client.Ascan().ScanAsUser(target, contextID, userID, "True", "", "", "")
		if errScanAsUser != nil {
			result, errFunc, scanId = nil, errScanAsUser, ""
			close(done)
		}
		scanId = scanResp["scan"].(string)
		// 7. Monitor status of scan
		client.monitorStatus(scanId, false)
		fmt.Println("Active Scan complete")

		// 8. Generate report
		report, errReport := client.Core().Jsonreport()
		if errReport != nil {
			result, errFunc, scanId = nil, errReport, ""
			close(done)
		}
		result, errFunc, scanId = report, nil, ""
		close(done)
	}()
	select {
	case <-ctx.Done():
		if scanSpiderId != "" {
			stopResponse, err := client.Spider().Stop(scanSpiderId)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(stopResponse)
		}
		if scanId != "" {
			stopResponse, err := client.Ascan().Stop(scanId)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(stopResponse)
		}
		if contextName != "" {
			respRemove, errRemoveContext := client.Context().RemoveContext(contextName)
			if errRemoveContext != nil {
				fmt.Println(errRemoveContext)
			}
			fmt.Println(respRemove)
		}
		return nil, fmt.Errorf("active scan cancelled or timed out")
	case <-done:
		if contextName != "" {
			respRemove, errRemoveContext := client.Context().RemoveContext(contextName)
			if errRemoveContext != nil {
				fmt.Println(errRemoveContext)
			}
			fmt.Println(respRemove)
		}
		return result, errFunc
	}
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

func (client *CliResult) passiveScan(target string, credential *dto.Credential, ctx context.Context) ([]byte, error) {
	var (
		result      []byte
		scanId      string
		contextName string
		errFunc     error
		done        = make(chan struct{})
	)
	go func() {
		if credential == nil {
			fmt.Println("Spider : " + target)
			resp, errScanSpider := client.Spider().Scan(target, "", "True", "", "")
			if errScanSpider != nil {
				result, errFunc, scanId = nil, errScanSpider, ""
			}
			scanId = resp["scan"].(string)
			client.monitorStatus(scanId, true)
			fmt.Println("Spider complete")

			// Wait for passive scan to finish
			for {
				time.Sleep(2 * time.Second)
				pscanStatus, errRecord := client.Pscan().RecordsToScan()
				if errRecord != nil {
					result, errFunc = nil, errRecord
					close(done)
				}
				records, _ := strconv.Atoi(pscanStatus["recordsToScan"].(string))
				fmt.Printf("Passive Scan records left: %d\n", records)
				if records == 0 {
					break
				}
			}
			fmt.Println("Passive Scan complete")

			report, errReport := client.Core().Jsonreport()
			if errReport != nil {
				result, errFunc, scanId = nil, errReport, ""
				close(done)
			}
			result, errFunc, scanId = report, nil, ""
			close(done)
		}

		contextName = "passive-context"
		// 1. Create context
		respContext, errNewContext := client.Context().NewContext(contextName)
		if errNewContext != nil {
			result, errFunc, scanId = nil, errNewContext, ""
			close(done)
		}
		contextID := respContext["contextId"].(string)

		// 2. Include target in context
		includeRegex := target + ".*"
		_, errIncludeInContext := client.Context().IncludeInContext(contextName, includeRegex)
		if errIncludeInContext != nil {
			result, errFunc, scanId = nil, errIncludeInContext, ""
			close(done)
		}

		// 3. Set authentication method (example: form-based)
		_, errAuthMethod := client.Authentication().SetAuthenticationMethod(
			contextID,
			"formBasedAuthentication",
			"loginUrl="+target,
		)
		if errAuthMethod != nil {
			result, errFunc, scanId = nil, errAuthMethod, ""
			close(done)
		}

		// 4. Add user with credentials
		userResp, errNewUser := client.Users().NewUser(contextID, "testuser")
		if errNewUser != nil {
			result, errFunc, scanId = nil, errNewUser, ""
			close(done)
		}

		userID := userResp["userId"].(string)
		_, errAuthCredential := client.Users().SetAuthenticationCredentials(
			contextID,
			userID,
			"username="+credential.User+"&password="+credential.Password,
		)
		if errAuthCredential != nil {
			result, errFunc, scanId = nil, errAuthCredential, ""
			close(done)
		}

		_, errSetUser := client.Users().SetUserEnabled(contextID, userID, "True")
		if errSetUser != nil {
			result, errFunc, scanId = nil, errSetUser, ""
			close(done)
		}

		// 5. Spider as user
		spiderResp, errScanAsUser := client.Spider().ScanAsUser(target, contextID, userID, "", "True", "")
		if errScanAsUser != nil {
			result, errFunc, scanId = nil, errScanAsUser, ""
			close(done)
		}
		scanId = spiderResp["scan"].(string)
		client.monitorStatus(scanId, true)
		fmt.Println("Spider as user complete")

		// 6. Wait for passive scan to finish
		for {
			time.Sleep(2 * time.Second)
			pscanStatus, errRecords := client.Pscan().RecordsToScan()
			if errRecords != nil {
				result, errFunc = nil, errRecords
				close(done)
			}
			records, _ := strconv.Atoi(pscanStatus["recordsToScan"].(string))
			fmt.Printf("Passive Scan records left: %d\n", records)
			if records == 0 {
				break
			}
		}
		fmt.Println("Passive Scan complete")

		// 7. Generate report
		report, errReport := client.Core().Jsonreport()
		if errReport != nil {
			result, errFunc, scanId = nil, errReport, ""
			close(done)
		}

		result, errFunc, scanId = report, nil, ""
		close(done)
	}()
	select {
	case <-ctx.Done():
		if scanId != "" {
			stopResponse, err := client.Spider().Stop(scanId)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(stopResponse)
		}
		if contextName != "" {
			respRemove, errRemoveContext := client.Context().RemoveContext(contextName)
			if errRemoveContext != nil {
				fmt.Println(errRemoveContext)
			}
			fmt.Println(respRemove)
		}
		return nil, fmt.Errorf("passive scan cancelled or timed out")
	case <-done:
		if contextName != "" {
			respRemove, errRemoveContext := client.Context().RemoveContext(contextName)
			if errRemoveContext != nil {
				fmt.Println(errRemoveContext)
			}
			fmt.Println(respRemove)
		}
		return result, errFunc
	}
}
