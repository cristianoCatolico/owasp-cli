package dto

type InstanceAlert struct {
	ID        string `json:"id"`
	URI       string `json:"uri"`
	Method    string `json:"method"`
	Param     string `json:"param"`
	Attack    string `json:"attack"`
	Evidence  string `json:"evidence"`
	OtherInfo string `json:"other_info"`
}
type Alert struct {
	PluginID        string          `json:"pluginid"`
	AlertRef        string          `json:"alertRef"`
	Alert           string          `json:"alert"`
	Name            string          `json:"name"`
	RiskCode        string          `json:"riskcode"`
	Confidence      string          `json:"confidence"`
	RiskDescription string          `json:"riskdesc"`
	Description     string          `json:"desc"`
	Instances       []InstanceAlert `json:"instances"`
	Count           string          `json:"count"`
	Solution        string          `json:"solution"`
	OtherInfo       string          `json:"other_info"`
	Reference       string          `json:"reference"`
	CweID           string          `json:"cweid"`
	WascID          string          `json:"wascid"`
	SourceID        string          `json:"sourceid"`
}

type Site struct {
	Alerts []Alert `json:"alerts"`
}

type JsonResult struct {
	Sites []Site `json:"site"`
}
