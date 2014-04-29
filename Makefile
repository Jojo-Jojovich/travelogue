test:
	@TEST=1 node node_modules/lab/bin/lab
test-cov:
	@TEST=1 node node_modules/lab/bin/lab -t 100
test-cov-html:
	@TEST=1 node node_modules/lab/bin/lab -r html -o coverage.html
complexity:
	@TEST=1 node node_modules/complexity-report/src/cli.js -o complexity.md -f markdown lib

.PHONY: test test-cov test-cov-html complexity

