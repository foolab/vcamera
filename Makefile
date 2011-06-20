obj-m := vcamera.o

all: module

install:
	make -C  /lib/modules/`uname -r`/build M=$(PWD) modules_install

clean:
	make -C  /lib/modules/`uname -r`/build M=$(PWD) clean

module:
	make -C  /lib/modules/`uname -r`/build M=$(PWD) modules
