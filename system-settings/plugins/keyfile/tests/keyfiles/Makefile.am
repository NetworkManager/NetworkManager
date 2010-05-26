EXTRA_DIST = \
	Test_Wired_Connection \
	Test_GSM_Connection \
	Test_Wireless_Connection \
	Test_Wired_Connection_MAC_Case \
	Test_Wired_Connection_IP6 \
	ATT_Data_Connect_BT \
	ATT_Data_Connect_Plain

check-local:
	@for f in $(EXTRA_DIST); do \
		chmod 0600 $(abs_srcdir)/$$f; \
	done

