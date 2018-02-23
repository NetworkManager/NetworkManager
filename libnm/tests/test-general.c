/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT SC WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-libnm-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

#define T(func, desc, expected) \
	result = func (desc); \
	g_assert_cmpstr (result, ==, expected); \
	g_free (result);

static void
test_fixup_desc_string (void)
{
	char *result = NULL;

	T (nm_utils_fixup_desc_string, NULL, NULL);
	T (nm_utils_fixup_desc_string, "", NULL);
	T (nm_utils_fixup_desc_string, "a", "a");
	T (nm_utils_fixup_desc_string, "a b", "a b");
	T (nm_utils_fixup_desc_string, "a b ", "a b");
	T (nm_utils_fixup_desc_string, "  a   bbc ", "a bbc");
	T (nm_utils_fixup_desc_string, "  a \xcc  bbc ", "a bbc");
	T (nm_utils_fixup_desc_string, "  a\xcc  bbc ", "a bbc");
	T (nm_utils_fixup_desc_string, "  a\xcc""bbc Wireless PC", "a bbc");
	T (nm_utils_fixup_desc_string, "  a\xcc""bbc Wireless PC ", "a bbc");
	T (nm_utils_fixup_desc_string, "  a\xcc""bbcWireless PC ", "a bbcWireless PC");
	T (nm_utils_fixup_desc_string, "  a\xcc""bbc Wireless PCx", "a bbc Wireless PCx");
}

static void
test_fixup_vendor_string (void)
{
	char *result = NULL;

	T (nm_utils_fixup_vendor_string, "3Com", "3Com");
	T (nm_utils_fixup_vendor_string, "3Com Corp.", "3Com");
	T (nm_utils_fixup_vendor_string, "3Com Corporation", "3Com");
	T (nm_utils_fixup_vendor_string, "Adaptec", "Adaptec");
	T (nm_utils_fixup_vendor_string, "ADMtek", "ADMtek");
	T (nm_utils_fixup_vendor_string, "ADMtek, Inc.", "ADMtek");
	T (nm_utils_fixup_vendor_string, "AEI", "AEI");
	T (nm_utils_fixup_vendor_string, "Airprime, Incorporated", "Airprime");
	T (nm_utils_fixup_vendor_string, "AirVast", "AirVast");
	T (nm_utils_fixup_vendor_string, "Alcatel Telecom", "Alcatel Telecom");
	T (nm_utils_fixup_vendor_string, "ALi Corp.", "ALi");
	T (nm_utils_fixup_vendor_string, "Allied Telesis", "Allied Telesis");
	T (nm_utils_fixup_vendor_string, "AnyDATA Corporation", "AnyDATA");
	T (nm_utils_fixup_vendor_string, "Apple Inc.", "Apple");
	T (nm_utils_fixup_vendor_string, "Apple, Inc.", "Apple");
	T (nm_utils_fixup_vendor_string, "ASUSTek Computer, Inc.", "ASUSTek Computer");
	T (nm_utils_fixup_vendor_string, "Atheros Communications", "Atheros");
	T (nm_utils_fixup_vendor_string, "Atheros Communications, Inc.", "Atheros");
	T (nm_utils_fixup_vendor_string, "AzureWave", "AzureWave");
	T (nm_utils_fixup_vendor_string, "Belkin", "Belkin");
	T (nm_utils_fixup_vendor_string, "Belkin Components", "Belkin");
	T (nm_utils_fixup_vendor_string, "Broadcom Corp.", "Broadcom");
	T (nm_utils_fixup_vendor_string, "Chelsio Communications Inc", "Chelsio");
	T (nm_utils_fixup_vendor_string, "CMOTECH Co., Ltd.", "CMOTECH");
	T (nm_utils_fixup_vendor_string, "Comneon", "Comneon");
	T (nm_utils_fixup_vendor_string, "Compex", "Compex");
	T (nm_utils_fixup_vendor_string, "Corega K.K.", "Corega K.K.");
	T (nm_utils_fixup_vendor_string, "Curitel Communications, Inc.", "Curitel");
	T (nm_utils_fixup_vendor_string, "Cypress Semiconductor Corp.", "Cypress");
	T (nm_utils_fixup_vendor_string, "Davicom Semiconductor, Inc.", "Davicom");
	T (nm_utils_fixup_vendor_string, "Digital Equipment Corporation", "Digital Equipment");
	T (nm_utils_fixup_vendor_string, "D-Link Corp.", "D-Link");
	T (nm_utils_fixup_vendor_string, "D-Link System", "D-Link System");
	T (nm_utils_fixup_vendor_string, "D-Link System Inc", "D-Link System");
	T (nm_utils_fixup_vendor_string, "DrayTek Corp.", "DrayTek");
	T (nm_utils_fixup_vendor_string, "d'TV", "d'TV");
	T (nm_utils_fixup_vendor_string, "DVICO", "DVICO");
	T (nm_utils_fixup_vendor_string, "Emulex Corporation", "Emulex");
	T (nm_utils_fixup_vendor_string, "EndPoints, Inc.", "EndPoints");
	T (nm_utils_fixup_vendor_string, "Entrega [hex]", "Entrega");
	T (nm_utils_fixup_vendor_string, "Ericsson Business Mobile Networks BV", "Ericsson");
	T (nm_utils_fixup_vendor_string, "Exar Corp.", "Exar");
	T (nm_utils_fixup_vendor_string, "Fiberline", "Fiberline");
	T (nm_utils_fixup_vendor_string, "Fujitsu Limited.", "Fujitsu");
	T (nm_utils_fixup_vendor_string, "Gateway, Inc.", "Gateway");
	T (nm_utils_fixup_vendor_string, "Gemtek", "Gemtek");
	T (nm_utils_fixup_vendor_string, "Genesys Logic, Inc.", "Genesys Logic");
	T (nm_utils_fixup_vendor_string, "GlobeSpan, Inc.", "GlobeSpan");
	T (nm_utils_fixup_vendor_string, "Gmate, Inc.", "Gmate");
	T (nm_utils_fixup_vendor_string, "Guillemot Corp.", "Guillemot");
	T (nm_utils_fixup_vendor_string, "Hewlett-Packard", "Hewlett-Packard");
	T (nm_utils_fixup_vendor_string, "Hirose Electric", "Hirose Electric");
	T (nm_utils_fixup_vendor_string, "Huawei-3Com", "Huawei-3Com");
	T (nm_utils_fixup_vendor_string, "ICS Advent", "ICS Advent");
	T (nm_utils_fixup_vendor_string, "Intel Corp.", "Intel");
	T (nm_utils_fixup_vendor_string, "Intel Corporation", "Intel");
	T (nm_utils_fixup_vendor_string, "Intellon Corp.", "Intellon");
	T (nm_utils_fixup_vendor_string, "InterBiometrics", "InterBiometrics");
	T (nm_utils_fixup_vendor_string, "Intersil Corp.", "Intersil");
	T (nm_utils_fixup_vendor_string, "Intersil Corporation", "Intersil");
	T (nm_utils_fixup_vendor_string, "I-O Data Device, Inc.", "I-O Data Device");
	T (nm_utils_fixup_vendor_string, "Jaton Corp.", "Jaton");
	T (nm_utils_fixup_vendor_string, "Kawasaki LSI", "Kawasaki LSI");
	T (nm_utils_fixup_vendor_string, "KTI", "KTI");
	T (nm_utils_fixup_vendor_string, "LapLink, Inc.", "LapLink");
	T (nm_utils_fixup_vendor_string, "Lenovo", "Lenovo");
	T (nm_utils_fixup_vendor_string, "LevelOne", "LevelOne");
	T (nm_utils_fixup_vendor_string, "Linksys, Inc.", "Linksys");
	T (nm_utils_fixup_vendor_string, "Linksys", "Linksys");
	T (nm_utils_fixup_vendor_string, "Lite-On Communications Inc", "Lite-On");
	T (nm_utils_fixup_vendor_string, "Logitec Corp.", "Logitec");
	T (nm_utils_fixup_vendor_string, "Logitech, Inc.", "Logitech");
	T (nm_utils_fixup_vendor_string, "LSI Corporation", "LSI");
	T (nm_utils_fixup_vendor_string, "Marvell Semiconductor, Inc.", "Marvell");
	T (nm_utils_fixup_vendor_string, "Marvell Technology Group Ltd.", "Marvell");
	T (nm_utils_fixup_vendor_string, "MediaTek Inc.", "MediaTek");
	T (nm_utils_fixup_vendor_string, "Memorex", "Memorex");
	T (nm_utils_fixup_vendor_string, "Micrel-Kendin", "Micrel-Kendin");
	T (nm_utils_fixup_vendor_string, "Microsoft Corp.", "Microsoft");
	T (nm_utils_fixup_vendor_string, "Microsoft Corporation", "Microsoft");
	T (nm_utils_fixup_vendor_string, "Mobility", "Mobility");
	T (nm_utils_fixup_vendor_string, "MosChip Semiconductor", "MosChip");
	T (nm_utils_fixup_vendor_string, "MYRICOM Inc.", "MYRICOM");
	T (nm_utils_fixup_vendor_string, "National Semiconductor Corporation", "National");
	T (nm_utils_fixup_vendor_string, "NEC Corp.", "NEC");
	T (nm_utils_fixup_vendor_string, "Netgear, Inc", "Netgear");
	T (nm_utils_fixup_vendor_string, "NetGear, Inc.", "NetGear");
	T (nm_utils_fixup_vendor_string, "Netgear", "Netgear");
	T (nm_utils_fixup_vendor_string, "Netopia, Inc.", "Netopia");
	T (nm_utils_fixup_vendor_string, "NetVin", "NetVin");
	T (nm_utils_fixup_vendor_string, "NetXen Incorporated", "NetXen");
	T (nm_utils_fixup_vendor_string, "Northern Telecom", "Northern Telecom");
	T (nm_utils_fixup_vendor_string, "NovaTech", "NovaTech");
	T (nm_utils_fixup_vendor_string, "Novatel Wireless", "Novatel Wireless");
	T (nm_utils_fixup_vendor_string, "NVIDIA Corp.", "NVIDIA");
	T (nm_utils_fixup_vendor_string, "NVIDIA Corporation", "NVIDIA");
	T (nm_utils_fixup_vendor_string, "Olicom", "Olicom");
	T (nm_utils_fixup_vendor_string, "OpenMoko, Inc.", "OpenMoko");
	T (nm_utils_fixup_vendor_string, "Option", "Option");
	T (nm_utils_fixup_vendor_string, "OQO", "OQO");
	T (nm_utils_fixup_vendor_string, "Ovislink Corp.", "Ovislink");
	T (nm_utils_fixup_vendor_string, "Packet Engines Inc.", "Packet Engines");
	T (nm_utils_fixup_vendor_string, "PEAK System", "PEAK System");
	T (nm_utils_fixup_vendor_string, "PEGATRON CORPORATION", "PEGATRON CORPORATION");
	T (nm_utils_fixup_vendor_string, "Planex Communications, Inc", "Planex");
	T (nm_utils_fixup_vendor_string, "Planex Communications", "Planex");
	T (nm_utils_fixup_vendor_string, "Planex", "Planex");
	T (nm_utils_fixup_vendor_string, "PLANEX", "PLANEX");
	T (nm_utils_fixup_vendor_string, "Portsmith", "Portsmith");
	T (nm_utils_fixup_vendor_string, "Qcom", "Qcom");
	T (nm_utils_fixup_vendor_string, "QLogic Corp.", "QLogic");
	T (nm_utils_fixup_vendor_string, "Qualcomm Atheros Communications", "Qualcomm Atheros");
	T (nm_utils_fixup_vendor_string, "Qualcomm Atheros", "Qualcomm Atheros");
	T (nm_utils_fixup_vendor_string, "Qualcomm, Inc.", "Qualcomm");
	T (nm_utils_fixup_vendor_string, "Quanta Computer, Inc.", "Quanta Computer");
	T (nm_utils_fixup_vendor_string, "Quantenna Communications, Inc.", "Quantenna");
	T (nm_utils_fixup_vendor_string, "RDC Semiconductor, Inc.", "RDC");
	T (nm_utils_fixup_vendor_string, "Realtek Semiconductor Co., Ltd.", "Realtek");
	T (nm_utils_fixup_vendor_string, "Realtek Semiconductor Corp.", "Realtek");
	T (nm_utils_fixup_vendor_string, "Red Hat, Inc.", "Red Hat");
	T (nm_utils_fixup_vendor_string, "Sagem", "Sagem");
	T (nm_utils_fixup_vendor_string, "Senao", "Senao");
	T (nm_utils_fixup_vendor_string, "Sharp Corp.", "Sharp");
	T (nm_utils_fixup_vendor_string, "Sierra Wireless, Inc.", "Sierra Wireless");
	T (nm_utils_fixup_vendor_string, "Silicom", "Silicom");
	T (nm_utils_fixup_vendor_string, "Sitecom", "Sitecom");
	T (nm_utils_fixup_vendor_string, "smartBridges, Inc.", "smartBridges");
	T (nm_utils_fixup_vendor_string, "SohoWare", "SohoWare");
	T (nm_utils_fixup_vendor_string, "Solarflare Communications", "Solarflare");
	T (nm_utils_fixup_vendor_string, "Sony Corp.", "Sony");
	T (nm_utils_fixup_vendor_string, "SpeedStream", "SpeedStream");
	T (nm_utils_fixup_vendor_string, "STMicroelectronics", "STMicroelectronics");
	T (nm_utils_fixup_vendor_string, "Sweex", "Sweex");
	T (nm_utils_fixup_vendor_string, "SysKonnect", "SysKonnect");
	T (nm_utils_fixup_vendor_string, "TDK Semiconductor Corp.", "TDK");
	T (nm_utils_fixup_vendor_string, "Toshiba Corp.", "Toshiba");
	T (nm_utils_fixup_vendor_string, "TRENDnet", "TRENDnet");
	T (nm_utils_fixup_vendor_string, "TwinMOS", "TwinMOS");
	T (nm_utils_fixup_vendor_string, "U.S. Robotics", "U.S. Robotics");
	T (nm_utils_fixup_vendor_string, "Vaillant", "Vaillant");
	T (nm_utils_fixup_vendor_string, "VMware", "VMware");
	T (nm_utils_fixup_vendor_string, "Wavecom", "Wavecom");
	T (nm_utils_fixup_vendor_string, "Westell", "Westell");
	T (nm_utils_fixup_vendor_string, "Wilocity Ltd.", "Wilocity");
	T (nm_utils_fixup_vendor_string, "Winbond", "Winbond");
	T (nm_utils_fixup_vendor_string, "Wistron NeWeb", "Wistron NeWeb");
	T (nm_utils_fixup_vendor_string, "Xircom", "Xircom");
	T (nm_utils_fixup_vendor_string, "Z-Com", "Z-Com");
	T (nm_utils_fixup_vendor_string, "Zinwell", "Zinwell");
	T (nm_utils_fixup_vendor_string, "ZyDAS", "ZyDAS");
	T (nm_utils_fixup_vendor_string, "ZyXEL Communications Corp.", "ZyXEL");
}

/*****************************************************************************/

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func ("/libnm/general/fixup_desc_string", test_fixup_desc_string);
	g_test_add_func ("/libnm/general/fixup_vendor_string", test_fixup_vendor_string);

	return g_test_run ();
}
