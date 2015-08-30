CC ?= gcc
CFLAGS ?= -Os -Wall -Wextra -ggdb
LDFLAGS += -lpcap
LDSLNK = $(LDFLAGS) -static
STRIP ?= strip
CP ?= cp
RM ?= rm -f
EXES = icmpdsl
SRCS = $(patsubst %,%.c,$(EXES))
OBJS = $(patsubst %.c,%.o,$(SRCS))
DBGX = $(patsubst %,%dbg,$(EXES))
SLNK = $(patsubst %,%static,$(EXES))

all: $(EXES)

static: $(SLNK)

$(EXES): $(DBGX)
	$(CP) $< $@
	$(STRIP) $@

$(DBGX): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(SLNK): $(OBJS)
	$(CC) -o $@ $^ $(LDSLNK)
	$(STRIP) $@

$(OBJS): $(SRCS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	$(RM) $(OBJS) $(EXES) $(DBGX) $(SLNK)
