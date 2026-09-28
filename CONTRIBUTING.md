# Contributing

Kurokagi is an independent implementation. Do not copy or adapt source from other scanners. Keep changes small, use idiomatic Go, and preserve conservative evidence rules. Never test arbitrary public targets; integration tests should use local controlled servers. Run gofmt, `go test ./...`, `go vet ./...`, and `go test -race ./...` before submitting. Include new safety cases when changing scope, request execution or response evaluation.
