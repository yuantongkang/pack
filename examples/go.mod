module github.com/buildpacks/examples

go 1.16

require (
	github.com/buildpacks/imgutil v0.0.0-20210818180451-66aea982d5dc
	github.com/buildpacks/pack v0.20.0
)

replace github.com/buildpacks/pack => ../
