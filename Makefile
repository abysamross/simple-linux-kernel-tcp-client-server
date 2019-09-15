ifneq ($(KERNELRELEASE), )

# Section that holds list of external modules to be built
#
# This section is used by the second pass `make' called 
# by kbuild from within the kernel build directory.
#
# The second pass is identifiled by a valid $(KERNELRELEASE)
#
# On newer kbuild this section can be separated and kept 
# in an individual `Kbuild' file as it is done here.
#
# But for compatiblity with older kbuild that recognizes 
# only Makefiles - Forcefully include Kbuild file here to 
# be used by second pass kbuild from kernel build directory
#
# Read Documentation/Kbuild/modules.txt for detailed explnation
#

include Kbuild

else

# Section to be used by the first `make' invocation from cmdline
#
# The `make' commands here change dir to the kernel build dir and
# invokes the kbuild `make' for target `modules', which will in turn 
# change dir into this directory, $(M), and build the modules listed 
# in the Kbuild file or in the section above
#

KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

endif
