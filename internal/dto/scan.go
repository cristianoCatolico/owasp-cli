package dto

type InstanceAlert struct {
	ID  string `json:"id"`
	URI string `json:"uri"`
	// This can be an enum since we have GET, POST, PUT, PATCH, DELETE
	Method string `json:"method"`
	// Can be empty string
	Param string `json:"param"`
	// Can be empty string
	Attack string `json:"attack"`
	// Can be empty string
	Evidence string `json:"evidence"`
	// Can be empty string
	OtherInfo string `json:"other_info"`
}
type Alert struct {
	PluginID string `json:"pluginid"`
	AlertRef string `json:"alertRef"`
	Alert    string `json:"alert"`
	Name     string `json:"name"`
	// "0" — Informational , "1" — Low , "2" — Medium, "3" — High
	RiskCode string `json:"riskcode"`
	// "0" — False Positive, "1" — Low, "2" — Medium, "3" — High
	Confidence string `json:"confidence"`
	// "Informational (Low)", "Informational (Medium)", "Low (Medium)", "Medium (Low)", "Medium (High)", "High (Medium)", "High (High)"
	RiskDescription string `json:"riskdesc"`
	// Can be empty
	Description string          `json:"desc"`
	Instances   []InstanceAlert `json:"instances"`
	Count       string          `json:"count"`
	// Can be empty
	Solution string `json:"solution"`
	// Can be empty string
	OtherInfo string `json:"other_info"`
	// Can be empty string
	Reference string `json:"reference"`
	CweID     string `json:"cweid"`
	WascID    string `json:"wascid"`
	SourceID  string `json:"sourceid"`
}

type Site struct {
	Alerts []Alert `json:"alerts"`
}

type JsonResult struct {
	Sites []Site `json:"site"`
}
