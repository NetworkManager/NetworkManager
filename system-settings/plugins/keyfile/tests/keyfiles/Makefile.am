EXTRA_DIST = \
	Test_Wired_Connection \
	Test_GSM_Connection \
	Test_Wireless_Connection

check-local:
	@for f in $(EXTRA_DIST); do \
		chmod 0600 $(abs_srcdir)/$$f; \
	done

