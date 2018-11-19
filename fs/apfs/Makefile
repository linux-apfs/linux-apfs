#
# Makefile for Linux Apple APFS filesystem driver.
#

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-$(CONFIG_APFS_FS) += apfs.o

apfs-y := btree.o dir.o file.o inode.o key.o message.o namei.o \
	  super.o symlink.o table.o unicode.o xattr.o

all:
	$(MAKE) -C /lib/modules/$(KERNELRELEASE)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KERNELRELEASE)/build M=$(PWD) clean

else
# external module build

EXTRA_FLAGS += -I$(PWD)

#
# KDIR is a path to a directory containing kernel source.
# It can be specified on the command line passed to make to enable the module to
# be built and installed for a kernel other than the one currently running.
# By default it is the path to the symbolic link created when
# the current kernel's modules were installed, but
# any valid path to the directory in which the target kernel's source is located
# can be provided on the command line.
#
KVER	?= $(shell uname -r)
KDIR	:= /lib/modules/$(KVER)/build
MDIR	:= /lib/modules/$(KVER)
PWD	:= $(shell pwd)
KREL	:= $(shell cd ${KDIR} && make -s kernelrelease)
PWD	:= $(shell pwd)

export CONFIG_APFS_FS := m

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

install:all
	rm -f ${DESTDIR}${MDIR}/kernel/fs/apfs/apfs.ko
	install -m644 -b -D apfs.ko ${DESTDIR}${MDIR}/kernel/fs/apfs/apfs.ko
ifeq ($(DESTDIR),)
		depmod -a
endif
uninstall:
	rm -rf ${DESTDIR}/${MDIR}/kernel/fs/apfs
ifeq ($(DESTDIR),)
		depmod -a
endif

endif

.PHONY : all clean install uninstall
