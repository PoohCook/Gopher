
MAKE = make

COMMON_DIR = ../
.PHONY: test update libs

clean:
	rm -f *.o *.so
	rm -rf extout

update:
	unity-update.sh

test:
	./RunAllUnitTests.py -f
	$(MAKE) lint

devtest:
	./DevUnitTests.py -f

lint:
	pycodestyle modules test --config=.pycodestyle.cfg
	pygount ./modules | awk '$$1 > 100'
