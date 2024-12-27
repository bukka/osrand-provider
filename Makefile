.PHONY: all check clean format

all:
	if [ ! -d "builddir" ]; then \
		meson setup builddir; \
	fi; \
	meson compile -C builddir osrand

check:
	meson test -C builddir

clean:
	rm -rf builddir

dist:
	rm -fr distdir
	meson setup distdir
	meson compile -C distdir pkcs11
	meson test -C distdir
	meson dist -C distdir

format:
	find src -name '*.c' -or -name '*.h' | xargs clang-format -i
