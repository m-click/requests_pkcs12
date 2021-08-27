# Copyright (C) m-click.aero GmbH
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

.DELETE_ON_ERROR:

.PHONY: usage
usage:
	@echo ''
	@echo 'Usage:'
	@echo ''
	@echo '    make clean'
	@echo '    make check'
	@echo '    make dist'
	@echo '    make release'
	@echo ''

.PHONY: clean
clean:
	rm -rf *.egg-info/ .venv __pycache__/ build/ dist/

.venv/finished:
	rm -rf .venv
	python3 -m venv .venv
	. .venv/bin/activate && python3 -m pip install --upgrade pip
	. .venv/bin/activate && python3 -m pip install -e '.[dev]'
	touch $@

.PHONY: check
check: .venv/finished
	. .venv/bin/activate && python3 -m requests_pkcs12

.PHONY: dist
dist: check .venv/finished
	rm -rf *.egg-info/ build/ dist/
	. .venv/bin/activate && python3 setup.py sdist
	. .venv/bin/activate && python3 setup.py bdist_wheel
	gpg --detach-sign -a dist/requests_pkcs12-*.tar.gz
	gpg --detach-sign -a dist/requests_pkcs12-*-py3-none-any.whl

.PHONY: release
release: clean
	[ "$$(git diff | wc -c)" = 0 ]
	$(MAKE) .venv/finished
	. .venv/bin/activate && python3 -c '\
	  old_version = open("version").read().strip(); \
	  new_version = old_version.replace(".dev0", ""); \
	  open("version", "w").write("{}\n".format(new_version))'
	$(MAKE) dist
	. .venv/bin/activate && python3 -m twine upload dist/requests_pkcs12-*
	git commit -am "Release $$(cat version)"
	git tag -sm "$$(cat version)" "$$(cat version)"
	. .venv/bin/activate && python3 -c '\
	  old_version = open("version").read().strip(); \
	  new_version = "1.{}.dev0".format(int(old_version.split(".")[1]) + 1); \
	  open("version", "w").write("{}\n".format(new_version))'
	git commit -am "Set version to $$(cat version)"
	git push
	git push --tags
