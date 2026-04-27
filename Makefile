.PHONY: terraform-fmt terraform-validate go-test python-check

terraform-fmt:
	cd exercises/01-secure-gcp-terraform/examples/basic && terraform fmt -recursive

terraform-validate:
	cd exercises/01-secure-gcp-terraform/examples/basic && terraform init -backend=false && terraform validate

go-test:
	cd exercises/03-automate-security-checks-go && go test ./...

python-check:
	cd exercises/04-automate-security-checks-python && python -m compileall .