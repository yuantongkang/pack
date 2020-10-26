package runtime

import (
	"context"
	"io"

	"github.com/docker/docker/api/types"
)

type Runtime interface {
	ImageInspect(ctx context.Context, imageName string) (types.ImageInspect, error)

	ImageTag(ctx context.Context, imageName, otherImageName string) error

	ImageLoad(ctx context.Context, tarReader io.Reader, /* TODO: Options */) (io.ReadCloser, error)

	// ImagePull pulls the image. 
	// 
	// Returns a streaming io.ReadCloser. Reader should always be consumed and closed. 
	// See jsonmessage.DisplayJSONMessagesToStream.   
	ImagePull(ctx context.Context, imageName string, /* TODO: Options */) (io.ReadCloser, error)

	// ImagePull requests that an image by pushed. 
	// 
	// Returns a streaming io.ReadCloser. Reader should always be consumed and closed. 
	// See jsonmessage.DisplayJSONMessagesToStream.   
	ImagePush(ctx context.Context, imageName string, /* TODO: Options */) (io.ReadCloser, error)

	ImageRemove(ctx context.Context, imageName string, /* TODO: Options */) ([]types.ImageDeleteResponseItem, error)
}
