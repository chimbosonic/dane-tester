watch-server:
	export RUST_LOG="info,dane=trace"; cargo watch -x "run --bin dane-tester-server"

test-cli-success:
	cargo run --package dane-tester-cli -- --user-id "alexis.lowe@chimbosonic.com"

test-cli-failure:
	cargo run --package dane-tester-cli -- --user-id "Joe.Doe@example.org"

update-root-hints:
	curl -sSf https://www.internic.net/domain/named.root -o dane/named.root
