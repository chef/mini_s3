REBAR=$(shell which rebar)
ifeq ($(REBAR),)
	$(error "Rebar not available on this system")
endif

APPDIR=$(CURDIR)
SRCDIR=$(APPDIR)/src
EBINDIR=$(APPDIR)/ebin

PLT_DIR=$(CURDIR)/.plt
DEPS_PLT=$(PLT_DIR)/mini_s3
DIALYZER_DEPS=ibrowse

ERLPATH=-pa $(EBINDIR) -pa $(APPDIR)/deps/*/ebin

.PHONY=all clean_plt dialyzer typer compile clean distclean test

all: compile test dialyzer

deps:
	$(REBAR) get-deps

$(PLT_DIR):
	mkdir -p $(PLT_DIR)

$(DEPS_PLT): $(PLT_DIR)
	dialyzer --build_plt --output_plt $(DEPS_PLT) \
		$(ERLPATH) --apps $(DIALYZER_DEPS)

clean_plt:
	rm -rf $(PLT_DIR)

dialyzer: $(DEPS_PLT)
	@dialyzer -Wrace_conditions -Wunderspecs \
        --plts ~/.dialyzer_plt $(DEPS_PLT) -r $(EBINDIR)

typer: compile $(PLT)
	typer --plt $(PLT) -r $(SRCDIR)

compile:
	$(REBAR) compile

test:
	$(REBAR) skip_deps=true eunit

clean:
	$(REBAR) clean

distclean: clean clean_plt
