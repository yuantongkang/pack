package runtime

import (
	"context"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

var _ = (client.CommonAPIClient)(&ClientWrapper{})

// ClientWrapper is an intermittent transitional object to be used to migrate from the CommonAPIClient to a Runtime. 
type ClientWrapper struct {
	client.CommonAPIClient
	runtime Runtime
}

func NewClientWrapper(client client.CommonAPIClient, runtime Runtime) *ClientWrapper {
	return &ClientWrapper{CommonAPIClient: client, runtime: runtime}
}

func (c *ClientWrapper) ImageInspectWithRaw(ctx context.Context, image string) (types.ImageInspect, []byte, error) {
	imageInspect, err := c.runtime.ImageInspect(ctx, image)
	return imageInspect, nil, err
}

func (c *ClientWrapper) ImageLoad(ctx context.Context, input io.Reader, quiet bool) (types.ImageLoadResponse, error) {
	load, err := c.runtime.ImageLoad(ctx, input)
	return types.ImageLoadResponse{Body: load, JSON: true}, err
}

func (c *ClientWrapper) ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error) {
	return c.runtime.ImagePull(ctx, ref)
}

func (c *ClientWrapper) ImagePush(ctx context.Context, ref string, options types.ImagePushOptions) (io.ReadCloser, error) {
	return c.runtime.ImagePush(ctx, ref)
}

func (c *ClientWrapper) ImageRemove(ctx context.Context, image string, options types.ImageRemoveOptions) ([]types.ImageDeleteResponseItem, error) {
	return c.runtime.ImageRemove(ctx, image)
}

func (c *ClientWrapper) ImageTag(ctx context.Context, image, ref string) error {
	return c.runtime.ImageTag(ctx, image, ref)
}
