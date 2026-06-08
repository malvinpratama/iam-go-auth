# iam-go-auth

The **auth** microservice of the IAM platform, built in Go. Independently built,
tested, versioned and deployed. Shared code comes from
[iam-go-contracts](https://github.com/malvinpratama/iam-go-contracts) and
[iam-go-libs](https://github.com/malvinpratama/iam-go-libs); orchestration,
compose and docs live in the umbrella repo
[iam-go](https://github.com/malvinpratama/iam-go).

```bash
make build && make test     # compile + unit tests
make docker                 # build the container image
```

For local cross-repo development, check out the sibling repos side by side and
use a `go.work` spanning them (do not commit it).
