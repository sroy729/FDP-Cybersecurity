subdirs := ramses profile

all: profile demo_victim.c
	gcc -o demo_victim demo_victim.c

.PHONY: all clean $(subdirs)

$(subdirs):
	@$(MAKE) -C $@

profile: ramses

clean:
	@for d in $(subdirs); do $(MAKE) -C $$d clean; done
