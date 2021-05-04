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
	@echo '    make dist'
	@echo '    make release'
	@echo ''

.PHONY: clean
clean:
	rm -rf *.egg-info/ build/ dist/

.PHONY: dist
dist: clean
	python3 setup.py sdist
	python3 setup.py bdist_wheel --universal
	gpg --detach-sign -a dist/requests_pkcs12-$$(python3 setup.py --version).tar.gz
	gpg --detach-sign -a dist/requests_pkcs12-$$(python3 setup.py --version)-py2.py3-none-any.whl

.PHONY: release
release:
	[ "$$(git diff | wc -c)" = 0 ]
	python3 -c '\
	  new_setup_py = open("setup.py").read().replace(".dev0", ""); \
	  open("setup.py", "w").write(new_setup_py)'
	$(MAKE) dist
	twine upload dist/requests_pkcs12-$$(python3 setup.py --version)*
	git commit -am "Release $$(python3 setup.py --version)"
	git tag -sm "$$(python3 setup.py --version)" "$$(python3 setup.py --version)"
	python3 -c '\
	  import subprocess; \
	  old_version = subprocess.check_output(["python3", "setup.py", "--version"], encoding="ascii").strip(); \
	  new_version = "1.{}.dev0".format(int(old_version.split(".")[1]) + 1); \
	  new_setup_py = open("setup.py").read().replace(old_version, new_version); \
	  open("setup.py", "w").write(new_setup_py)'
	git commit -am "Set version to $$(python3 setup.py --version)"
	git push --tags
