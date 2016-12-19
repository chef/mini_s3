#
# Simple Makefile for rebar3 based erlang project
#

#
# Use rebar3 from either:
# - ./rebar3
# - rebar3 on the PATH (found via which)
# - Downloaded from $REBAR3_URL
#
REBAR3_URL=https://s3.amazonaws.com/rebar3/rebar3
ifeq ($(wildcard rebar3),rebar3)
  REBAR3 = $(CURDIR)/rebar3
endif

# Fallback to rebar on PATH
REBAR3 ?= $(shell which rebar3)

# And finally, prep to download rebar if all else fails
ifeq ($(REBAR3),)
REBAR3 = rebar3
endif

all: $(REBAR3)
	@$(REBAR3) do clean, compile, eunit, dialyzer

rel: all
	@$(REBAR3) release

test:
	@$(REBAR3) eunit ct

dialyzer:
	@$(REBAR3) dialyzer

xref:
	@$(REBAR3) xref

update:
	@$(REBAR3) update

install: $(REBAR3) distclean update

distclean:
	@rm -rf _build

$(REBAR3):
	curl -Lo rebar3 $(REBAR3_URL) || wget $(REBAR3_URL)
	chmod a+x rebar3

travis: all
	@echo "Travis'd!"
