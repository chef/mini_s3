REBAR=$(shell which rebar)
ifeq ($(REBAR),)
	$(error "Rebar not available on this system")
endif

APPDIR=$(CURDIR)
SRCDIR=$(APPDIR)/src
EBINDIR=$(APPDIR)/ebin

PLT_DIR=$(CURDIR)/.plt
PLT=$(PLT_DIR)/dialyzer_plt

ERLPATH=-pa $(EBINDIR)

.PHONY=all clean_plt dialyzer typer build clean distclean

all: build

$(PLT_DIR):
	mkdir -p $(PLT_DIR)

$(PLT): $(PLT_DIR)
	dialyzer --build_plt --output_plt $(PLT) \
		$(ERLPATH) \
		--apps erts kernel stdlib sasl eunit public_key \
		crypto ssl xmerl inets compiler asn1 mnesia tools

clean_plt:
	rm -rf $(PLT_DIR)

dialyzer: $(PLT)
	@rebar compile
	dialyzer --no_check_plt --src --plt $(PLT) \
	$(ERLPATH) \
	-c $(SRCDIR)

typer: build $(PLT)
	typer --plt $(PLT) -r $(SRCDIR)

build:
	$(REBAR) compile

eunit : build
	$(REBAR) skip_deps=true eunit

clean:
	$(REBAR) clean

distclean: clean clean_plt
