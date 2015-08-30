CC ?= gcc
CFLAGS ?= -Os -Wall -Wextra -ggdb
LDFLAGS += -lpcap
LDXTRA += 
LDSLNK = $(LDFLAGS) -static
LDXSLN = $(LDXTRA) -static
STRIP ?= strip
CP ?= cp
RM ?= rm -f
EXES = icmpdsl
SRCS = $(patsubst %,%.c,$(EXES))
OBJS = $(patsubst %,%.o,$(EXES))
DBGX = $(patsubst %,%dbg,$(EXES))
SLNK = $(patsubst %,%static,$(EXES))
XTRA = nfqdsl
XSRC = $(patsubst %,%.c,$(XTRA))
XOBJ = $(patsubst %,%.o,$(XTRA))
XDBG = $(patsubst %,%dbg,$(XTRA))
XSLN = $(patsubst %,%static,$(XTRA))

all: $(EXES)

static: $(SLNK)

$(EXES): $(DBGX)
	$(CP) $< $@
	$(STRIP) $@

$(XTRA): $(XDBG)
	$(CP) $< $@
	$(STRIP) $@

$(DBGX): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(XDBG): $(XOBJ)
	$(CC) -o $@ $^ $(LDXTRA)

$(SLNK): $(OBJS)
	$(CC) -o $@ $^ $(LDSLNK)
	$(STRIP) $@

$(XSLN): $(XOBJ)
	$(CC) -o $@ $^ $(LDXSLN)
	$(STRIP) $@

$(OBJS): $(SRCS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(XOBJ): $(XSRC)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	$(RM) $(OBJS) $(EXES) $(DBGX) $(SLNK) $(XOBJ) $(XTRA) $(XDBG) $(XSLN)
