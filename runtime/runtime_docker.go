package runtime

import "github.com/docker/docker/client"

type Docker struct {
	client client.CommonAPIClient
}

func NewDocker(client client.CommonAPIClient) *Docker {
	return &Docker{client: client}
}

func (d *Docker) Start() error {
	return nil
}

func (d *Docker) Shutdown()  error {
	return nil
}