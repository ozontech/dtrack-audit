BIN = dtrack-audit

default:
	$(MAKE) build

build:
	go build -o $(BIN) ./cmd/dtrack-audit/

clean:
	rm -f $(BIN)

.PHONY: build clean
