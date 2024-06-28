# "apxs" is searched in all directories of your PATH variable.
# If apxs cannot be found during the make process, you can adjust
# the path, i.e.:
APXS = apxs

MODULE_NAME = rewrite_fwfunc
APACHE_MODULE = mod_rewrite_fwfunc.so

SRCS = mod_rewrite_fwfunc.c
OBJS = mod_rewrite_fwfunc.o

RM = rm -f
LN = ln -sf
CP = cp -f

#CFLAGS += -DNDEBUG
#CFLAGS +=  -DDEBUG

CFLAGS = -Wc,-Wall $(MYSQCPPFLAGS) -DMODULE_NAME=$(MODULE_NAME) -DMODULE_NAME_module=$(MODULE_NAME)_module
LDFLAGS = -lssl -o $(APACHE_MODULE)

default: all

all: $(APACHE_MODULE)

$(APACHE_MODULE): $(SRCS)
	$(APXS) -c $(CFLAGS) $(LDFLAGS) $(SRCS)

install: all
	$(APXS) -i -a -n $(MODULE_NAME) ./.libs/$(APACHE_MODULE)

clean:
	$(RM) $(OBJS) $(APACHE_MODULE)
