
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

devtest:
	./DevUnitTests.py -f

lint:
	pycodestyle modules/dispext test --config=.pycodestyle.cfg
	pygount ./modules | awk '$$1 > 100'
