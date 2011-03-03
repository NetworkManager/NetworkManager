KEYFILES = \
	Test_Wired_Connection \
	Test_GSM_Connection \
	Test_Wireless_Connection \
	Test_Wired_Connection_MAC_Case \
	Test_Wired_Connection_IP6 \
	ATT_Data_Connect_BT \
	ATT_Data_Connect_Plain \
	Test_String_SSID \
	Test_Wired_TLS_Old \
	Test_Wired_TLS_New

CERTS = \
	test-ca-cert.pem \
	test-key-and-cert.pem

EXTRA_DIST = $(KEYFILES) $(CERTS)

check-local:
	@for f in $(KEYFILES); do \
		chmod 0600 $(abs_srcdir)/$$f; \
	done

