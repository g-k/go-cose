

install:
	dep ensure || echo "go dep not found (try https://golang.github.io/dep/docs/installation.html)"
	test -d test &&	mkdir -p test
	cd test && git clone https://github.com/cose-wg/Examples.git cose-wg-examples || true
	cd test && git clone https://github.com/franziskuskiefer/cose-rust.git || true
	# github doesn't support git archive
	# cd test && git archive --remote=https://github.com/mozilla/gecko-dev.git master security/manager/ssl/tests/unit/ | tar xvf -

lint:
	golint

coverage:
	go test -coverprofile=coverage.out && go tool cover -html=coverage.out

what-todo:
	git grep -i TODO

util/data:
	mkdir -p util/data

util/data/tags.csv: util/data
	cd util/data && wget 'https://www.iana.org/assignments/cbor-tags/tags.csv'

util/data/algorithms.csv: util/data
	cd util/data && wget 'https://www.iana.org/assignments/cose/algorithms.csv'

util/data/elliptic-curves.csv: util/data
	cd util/data && wget 'https://www.iana.org/assignments/cose/elliptic-curves.csv'

iana-csvs: util/data/tags.csv util/data/algorithms.csv util/data/elliptic-curves.csv

iana-codegen:
	go run util/cmd/from_csv.go

ci: install coverage lint
