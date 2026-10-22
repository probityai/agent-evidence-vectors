set +e
export PATH="$HOME/.local/bin:$PATH"
step(){ n="$1"; shift; "$@" > "/tmp/l5_$n.log" 2>&1; rc=$?; echo "STEP $n rc=$rc"; if [ $rc -ne 0 ]; then tail -25 "/tmp/l5_$n.log" | cut -c1-400; fi; }
step sync uv sync --python 3.13 --locked --extra dev --extra generators
step gofmt sh -c 'test -z "$(gofmt -l aee cmd corpora)"'
step build go build ./...
step vet go vet ./corpora/... ./aee/... ./cmd/...
step test go test ./aee/... ./cmd/... ./corpora/... -race -count=1
step cyclo-go uv run --python 3.13 python scripts/complexity-table-gate.py --rail go
step cyclo-py uv run --python 3.13 python scripts/complexity-table-gate.py --rail python
step staticcheck sh -c 'go run honnef.co/go/tools/cmd/staticcheck@latest ./corpora/... 2>&1 | head -20; true'
echo ALLDONE
