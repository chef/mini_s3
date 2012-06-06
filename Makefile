REBAR=$(shell which rebar)
ifeq ($(REBAR),)
	$(error "Rebar not available on this system")
endif

all:
	$(REBAR) compile

clean:
	$(REBAR) clean
