

install:
	test -d test &&	mkdir -p test
	cd test && git clone https://github.com/cose-wg/Examples.git cose-wg-examples || true
	cd test && git clone https://github.com/franziskuskiefer/cose-rust.git || true

coverage:
	go test -coverprofile=coverage.out && go tool cover -html=coverage.out
