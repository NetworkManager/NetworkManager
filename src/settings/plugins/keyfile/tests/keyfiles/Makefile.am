KEYFILES = \
	Test_Wired_Connection \
	Test_GSM_Connection \
	Test_Wireless_Connection \
	Test_Wired_Connection_MAC_Case \
	Test_MAC_Old_Format \
	Test_MAC_IB_Old_Format \
	Test_Wired_Connection_IP6 \
	ATT_Data_Connect_BT \
	ATT_Data_Connect_Plain \
	Test_String_SSID \
	Test_Intlist_SSID \
	Test_Intlike_SSID \
	Test_Intlike_SSID_2 \
	Test_Wired_TLS_Old \
	Test_Wired_TLS_New \
	Test_Wired_TLS_Blob \
	Test_Wired_TLS_Path_Missing \
	Test_InfiniBand_Connection \
	Test_Bridge_Main \
	Test_Bridge_Component \
	Test_New_Wired_Group_Name \
	Test_New_Wireless_Group_Names \
	Test_Missing_Vlan_Setting

CERTS = \
	test-ca-cert.pem \
	test-key-and-cert.pem

EXTRA_DIST = $(KEYFILES) $(CERTS)

check-local:
	@for f in $(KEYFILES); do \
		chmod 0600 $(abs_srcdir)/$$f; \
	done

