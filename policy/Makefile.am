polkit_policydir = $(datadir)/PolicyKit/policy

dist_polkit_policy_DATA =    				\
	org.freedesktop.network-manager-settings.system.policy

check:
	@for f in $(dist_polkit_policy_DATA); do \
            echo -n "Validate PolicyKit policy in $$f : "; \
            $(POLKIT_POLICY_FILE_VALIDATE) $(srcdir)/$$f ; \
	    ret=$$?; \
            if  [ "$$ret" = "0" ]; \
	      then \
                echo ok; \
            else \
                echo failed; \
		exit 1; \
            fi; \
        done;

clean-local :
	rm -f *~

