
### Architecture

TODO: Move to ascii or publicly available doc

https://docs.google.com/drawings/d/1u6qBLlu45Gq7bHyf_MN4hm1ylGyn9tEsSZywpn7LkKY/edit

### Regenerate proto


```bash
# from project root
protoc -I runtime/ runtime/runtime.proto --go_out=plugins=grpc:runtime/
```