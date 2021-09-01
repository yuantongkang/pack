package client_test

import (
	"context"
	"fmt"

	"github.com/buildpacks/imgutil"
	"github.com/buildpacks/pack"
	"github.com/buildpacks/pack/internal/image"
)

type customFetcher struct{}

func (f *customFetcher) Fetch(_ context.Context, _ string, _ image.FetchOptions) (imgutil.Image, error) {
	return nil, nil
}

var _ pack.ImageFetcher = (*customFetcher)(nil)

// The example shows a few replacable components
func Example_configure() {
	// create a context object
	context := context.Background()

	// initialize a pack client with configuration
	client, err := pack.NewClient(
		pack.WithFetcher(&customFetcher{}),
	)
	if err != nil {
		panic(err)
	}

	// build an image
	fmt.Println("building application image")
	err = client.Build(context, pack.BuildOptions{
		Image:        "pack-lib-test-image:0.0.1",
		AppPath:      "local/path/to/application/root",
		TrustBuilder: true,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("build completed")
}
