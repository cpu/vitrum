package main

type habEvent struct {
	Status string `json:"status"`
	Data   string `json:"data"`
}

type habStatus struct {
	Status   string     `json:"status"`
	Config   string     `json:"config"`
	State    string     `json:"state"`
	Failures int        `json:"failures"`
	Events   []habEvent `json:"events"`
}
