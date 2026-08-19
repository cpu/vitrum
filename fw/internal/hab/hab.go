package hab

type Event struct {
	Status string `json:"status"`
	Data   string `json:"data"`
}

type Status struct {
	Status   string  `json:"status"`
	Config   string  `json:"config"`
	State    string  `json:"state"`
	Failures int     `json:"failures"`
	Events   []Event `json:"events"`
}
