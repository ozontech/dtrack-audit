BIN = dtrack-audit

default:
	$(MAKE) build

build:
	env GOOS=linux GOARCH=amd64 go build -o $(BIN) ./cmd/dtrack-audit/
	env GOOS=windows GOARCH=386 go build -o $(BIN).exe ./cmd/dtrack-audit/

clean:
	rm -f $(BIN)
	rm -f $(BIN).exe

.PHONY: build clean
