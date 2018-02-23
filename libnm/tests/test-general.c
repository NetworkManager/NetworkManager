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
	T (nm_utils_fixup_vendor_string, "Abocom Systems Inc", "Abocom");
	T (nm_utils_fixup_vendor_string, "AboCom Systems Inc", "AboCom");
	T (nm_utils_fixup_vendor_string, "Accton Technology Corp.", "Accton");
	T (nm_utils_fixup_vendor_string, "Accton Technology Corporation", "Accton");
	T (nm_utils_fixup_vendor_string, "Acer Communications & Multimedia", "Acer");
	T (nm_utils_fixup_vendor_string, "Actiontec Electronics, Inc. [hex]", "Actiontec");
	T (nm_utils_fixup_vendor_string, "Adaptec", "Adaptec");
	T (nm_utils_fixup_vendor_string, "Addtron Technology Co, Inc.", "Addtron");
	T (nm_utils_fixup_vendor_string, "ADMtek", "ADMtek");
	T (nm_utils_fixup_vendor_string, "ADMtek, Inc.", "ADMtek");
	T (nm_utils_fixup_vendor_string, "ADS Technologies, Inc.", "ADS");
	T (nm_utils_fixup_vendor_string, "Advanced Micro Devices, Inc. [AMD]", "AMD");
	T (nm_utils_fixup_vendor_string, "Advance Multimedia Internet Technology Inc. (AMIT)", "Advance");
	T (nm_utils_fixup_vendor_string, "AEI", "AEI");
	T (nm_utils_fixup_vendor_string, "Airprime, Incorporated", "Airprime");
	T (nm_utils_fixup_vendor_string, "AirTies Wireless Networks", "AirTies");
	T (nm_utils_fixup_vendor_string, "AirVast", "AirVast");
	T (nm_utils_fixup_vendor_string, "Alcatel Telecom", "Alcatel Telecom");
	T (nm_utils_fixup_vendor_string, "ALi Corp.", "ALi");
	T (nm_utils_fixup_vendor_string, "Allied Telesis", "Allied Telesis");
	T (nm_utils_fixup_vendor_string, "Allied Telesyn International", "Allied Telesyn");
	T (nm_utils_fixup_vendor_string, "Alteon Networks Inc.", "Alteon");
	T (nm_utils_fixup_vendor_string, "Altima (nee Broadcom)", "Altima");
	T (nm_utils_fixup_vendor_string, "A-Max Technology Macao Commercial Offshore Co. Ltd.", "A-Max");
	T (nm_utils_fixup_vendor_string, "Amigo Technology Inc.", "Amigo");
	T (nm_utils_fixup_vendor_string, "AMIT Technology, Inc.", "AMIT");
	T (nm_utils_fixup_vendor_string, "Anchor Chips, Inc.", "Anchor");
	T (nm_utils_fixup_vendor_string, "AnyDATA Corporation", "AnyDATA");
	T (nm_utils_fixup_vendor_string, "Apple Inc.", "Apple");
	T (nm_utils_fixup_vendor_string, "Apple, Inc.", "Apple");
	T (nm_utils_fixup_vendor_string, "ARC International", "ARC");
	T (nm_utils_fixup_vendor_string, "ASIX Electronics Corp.", "ASIX");
	T (nm_utils_fixup_vendor_string, "Asix Electronics Corporation", "Asix");
	T (nm_utils_fixup_vendor_string, "Askey Computer Corp. [hex]", "Askey");
	T (nm_utils_fixup_vendor_string, "ASUSTek Computer, Inc.", "ASUSTek Computer");
	T (nm_utils_fixup_vendor_string, "ASUSTek Computer, Inc. (wrong ID)", "ASUSTek Computer");
	T (nm_utils_fixup_vendor_string, "ATEN International Co., Ltd", "ATEN");
	T (nm_utils_fixup_vendor_string, "Atheros Communications", "Atheros");
	T (nm_utils_fixup_vendor_string, "Atheros Communications, Inc.", "Atheros");
	T (nm_utils_fixup_vendor_string, "AVM GmbH", "AVM");
	T (nm_utils_fixup_vendor_string, "AzureWave", "AzureWave");
	T (nm_utils_fixup_vendor_string, "Belkin", "Belkin");
	T (nm_utils_fixup_vendor_string, "Belkin Components", "Belkin");
	T (nm_utils_fixup_vendor_string, "Billionton Systems, Inc.", "Billionton");
	T (nm_utils_fixup_vendor_string, "Broadcom Corp.", "Broadcom");
	T (nm_utils_fixup_vendor_string, "Broadcom Limited", "Broadcom");
	T (nm_utils_fixup_vendor_string, "Brocade Communications Systems, Inc.", "Brocade");
	T (nm_utils_fixup_vendor_string, "BUFFALO INC. (formerly MelCo., Inc.)", "BUFFALO");
	T (nm_utils_fixup_vendor_string, "CACE Technologies Inc.", "CACE");
	T (nm_utils_fixup_vendor_string, "Cadence Design Systems, Inc.", "Cadence");
	T (nm_utils_fixup_vendor_string, "Chelsio Communications Inc", "Chelsio");
	T (nm_utils_fixup_vendor_string, "Chicony Electronics Co., Ltd", "Chicony");
	T (nm_utils_fixup_vendor_string, "Chu Yuen Enterprise Co., Ltd", "Chu Yuen");
	T (nm_utils_fixup_vendor_string, "Cisco Systems Inc", "Cisco");
	T (nm_utils_fixup_vendor_string, "Cisco Systems, Inc.", "Cisco");
	T (nm_utils_fixup_vendor_string, "CMOTECH Co., Ltd.", "CMOTECH");
	T (nm_utils_fixup_vendor_string, "CNet Technology Inc.", "CNet");
	T (nm_utils_fixup_vendor_string, "CNet Technology Inc", "CNet");
	T (nm_utils_fixup_vendor_string, "Comneon", "Comneon");
	T (nm_utils_fixup_vendor_string, "Compaq Computer Corp.", "Compaq");
	T (nm_utils_fixup_vendor_string, "Compaq Computer Corporation", "Compaq");
	T (nm_utils_fixup_vendor_string, "Compex", "Compex");
	T (nm_utils_fixup_vendor_string, "Computer Access Technology Corp.", "Computer Access");
	T (nm_utils_fixup_vendor_string, "Conexant Systems, Inc.", "Conexant");
	T (nm_utils_fixup_vendor_string, "Conexant Systems (Rockwell), Inc.", "Conexant");
	T (nm_utils_fixup_vendor_string, "Corega K.K.", "Corega K.K.");
	T (nm_utils_fixup_vendor_string, "Curitel Communications, Inc.", "Curitel");
	T (nm_utils_fixup_vendor_string, "CyberTAN Technology", "CyberTAN");
	T (nm_utils_fixup_vendor_string, "Cypress Semiconductor Corp.", "Cypress");
	T (nm_utils_fixup_vendor_string, "Davicom Semiconductor, Inc.", "Davicom");
	T (nm_utils_fixup_vendor_string, "Dell Computer Corp.", "Dell");
	T (nm_utils_fixup_vendor_string, "DELTA Electronics, Inc", "DELTA");
	T (nm_utils_fixup_vendor_string, "Digital Equipment Corporation", "Digital Equipment");
	T (nm_utils_fixup_vendor_string, "D-Link Corp.", "D-Link");
	T (nm_utils_fixup_vendor_string, "D-Link System", "D-Link System");
	T (nm_utils_fixup_vendor_string, "D-Link System Inc", "D-Link System");
	T (nm_utils_fixup_vendor_string, "DrayTek Corp.", "DrayTek");
	T (nm_utils_fixup_vendor_string, "d'TV", "d'TV");
	T (nm_utils_fixup_vendor_string, "DVICO", "DVICO");
	T (nm_utils_fixup_vendor_string, "Edimax Computer Co.", "Edimax");
	T (nm_utils_fixup_vendor_string, "Edimax Technology Co., Ltd", "Edimax");
	T (nm_utils_fixup_vendor_string, "Efar Microsystems", "Efar");
	T (nm_utils_fixup_vendor_string, "Efficient Networks, Inc.", "Efficient");
	T (nm_utils_fixup_vendor_string, "ELCON Systemtechnik", "ELCON");
	T (nm_utils_fixup_vendor_string, "Elecom Co., Ltd", "Elecom");
	T (nm_utils_fixup_vendor_string, "ELSA AG", "ELSA");
	T (nm_utils_fixup_vendor_string, "Emulex Corporation", "Emulex");
	T (nm_utils_fixup_vendor_string, "Encore Electronics Inc.", "Encore");
	T (nm_utils_fixup_vendor_string, "EndPoints, Inc.", "EndPoints");
	T (nm_utils_fixup_vendor_string, "Entrega [hex]", "Entrega");
	T (nm_utils_fixup_vendor_string, "Ericsson Business Mobile Networks BV", "Ericsson");
	T (nm_utils_fixup_vendor_string, "eTEK Labs", "eTEK");
	T (nm_utils_fixup_vendor_string, "Exar Corp.", "Exar");
	T (nm_utils_fixup_vendor_string, "Fiberline", "Fiberline");
	T (nm_utils_fixup_vendor_string, "Fujitsu Limited.", "Fujitsu");
	T (nm_utils_fixup_vendor_string, "Fujitsu Siemens Computers", "Fujitsu Siemens");
	T (nm_utils_fixup_vendor_string, "Gateway, Inc.", "Gateway");
	T (nm_utils_fixup_vendor_string, "Gemtek", "Gemtek");
	T (nm_utils_fixup_vendor_string, "Genesys Logic, Inc.", "Genesys Logic");
	T (nm_utils_fixup_vendor_string, "Global Sun Technology", "Global Sun");
	T (nm_utils_fixup_vendor_string, "Global Sun Technology, Inc.", "Global Sun");
	T (nm_utils_fixup_vendor_string, "GlobeSpan, Inc.", "GlobeSpan");
	T (nm_utils_fixup_vendor_string, "Gmate, Inc.", "Gmate");
	T (nm_utils_fixup_vendor_string, "Good Way Technology", "Good Way");
	T (nm_utils_fixup_vendor_string, "Guillemot Corp.", "Guillemot");
	T (nm_utils_fixup_vendor_string, "Hangzhou Silan Microelectronics Co., Ltd.", "Hangzhou Silan");
	T (nm_utils_fixup_vendor_string, "Hawking Technologies", "Hawking");
	T (nm_utils_fixup_vendor_string, "Hewlett-Packard", "Hewlett-Packard");
	T (nm_utils_fixup_vendor_string, "Hirose Electric", "Hirose Electric");
	T (nm_utils_fixup_vendor_string, "Holtek Microelectronics Inc", "Holtek");
	T (nm_utils_fixup_vendor_string, "Huawei-3Com", "Huawei-3Com");
	T (nm_utils_fixup_vendor_string, "Huawei Technologies Co., Ltd.", "Huawei");
	T (nm_utils_fixup_vendor_string, "ICS Advent", "ICS Advent");
	T (nm_utils_fixup_vendor_string, "IMC Networks", "IMC");
	T (nm_utils_fixup_vendor_string, "Intel Corp.", "Intel");
	T (nm_utils_fixup_vendor_string, "Intel Corporation", "Intel");
	T (nm_utils_fixup_vendor_string, "Intellon Corp.", "Intellon");
	T (nm_utils_fixup_vendor_string, "InterBiometrics", "InterBiometrics");
	T (nm_utils_fixup_vendor_string, "Intersil Corp.", "Intersil");
	T (nm_utils_fixup_vendor_string, "Intersil Corporation", "Intersil");
	T (nm_utils_fixup_vendor_string, "I-O Data Device, Inc.", "I-O Data Device");
	T (nm_utils_fixup_vendor_string, "Jaton Corp.", "Jaton");
	T (nm_utils_fixup_vendor_string, "JMicron Technology Corp.", "JMicron");
	T (nm_utils_fixup_vendor_string, "Kawasaki LSI", "Kawasaki LSI");
	T (nm_utils_fixup_vendor_string, "KC Technology, Inc.", "KC");
	T (nm_utils_fixup_vendor_string, "Kingston Technology", "Kingston");
	T (nm_utils_fixup_vendor_string, "KTI", "KTI");
	T (nm_utils_fixup_vendor_string, "Kvaser AB", "Kvaser");
	T (nm_utils_fixup_vendor_string, "LapLink, Inc.", "LapLink");
	T (nm_utils_fixup_vendor_string, "Lenovo", "Lenovo");
	T (nm_utils_fixup_vendor_string, "LevelOne", "LevelOne");
	T (nm_utils_fixup_vendor_string, "LG Electronics, Inc.", "LG");
	T (nm_utils_fixup_vendor_string, "LG Electronics USA, Inc.", "LG");
	T (nm_utils_fixup_vendor_string, "Linksys, Inc.", "Linksys");
	T (nm_utils_fixup_vendor_string, "Linksys (?)", "Linksys");
	T (nm_utils_fixup_vendor_string, "Linksys", "Linksys");
	T (nm_utils_fixup_vendor_string, "Lite-On Communications Inc", "Lite-On");
	T (nm_utils_fixup_vendor_string, "Lite-On Technology Corp.", "Lite-On");
	T (nm_utils_fixup_vendor_string, "Logitec Corp.", "Logitec");
	T (nm_utils_fixup_vendor_string, "Logitech, Inc.", "Logitech");
	T (nm_utils_fixup_vendor_string, "LSI Corporation", "LSI");
	T (nm_utils_fixup_vendor_string, "LSI Logic / Symbios Logic", "LSI Logic");
	T (nm_utils_fixup_vendor_string, "Macronix, Inc. [MXIC]", "MXIC");
	T (nm_utils_fixup_vendor_string, "Marvell Semiconductor, Inc.", "Marvell");
	T (nm_utils_fixup_vendor_string, "Marvell Technology Group Ltd.", "Marvell");
	T (nm_utils_fixup_vendor_string, "MediaTek Inc.", "MediaTek");
	T (nm_utils_fixup_vendor_string, "Mellanox Technologies", "Mellanox");
	T (nm_utils_fixup_vendor_string, "Memorex", "Memorex");
	T (nm_utils_fixup_vendor_string, "Micrel-Kendin", "Micrel-Kendin");
	T (nm_utils_fixup_vendor_string, "Microchip Technology, Inc.", "Microchip");
	T (nm_utils_fixup_vendor_string, "Microcomputer Systems (M) Son", "Microcomputer");
	T (nm_utils_fixup_vendor_string, "Microsoft Corp.", "Microsoft");
	T (nm_utils_fixup_vendor_string, "Microsoft Corporation", "Microsoft");
	T (nm_utils_fixup_vendor_string, "Micro-Star International Co., Ltd. [MSI]", "MSI");
	T (nm_utils_fixup_vendor_string, "Micro Star International", "Micro Star");
	T (nm_utils_fixup_vendor_string, "Mobility", "Mobility");
	T (nm_utils_fixup_vendor_string, "MosChip Semiconductor", "MosChip");
	T (nm_utils_fixup_vendor_string, "Motorola PCS", "Motorola");
	T (nm_utils_fixup_vendor_string, "MYRICOM Inc.", "MYRICOM");
	T (nm_utils_fixup_vendor_string, "MYSON Technology Inc", "MYSON");
	T (nm_utils_fixup_vendor_string, "National Instruments Corp.", "National");
	T (nm_utils_fixup_vendor_string, "National Semiconductor Corporation", "National");
	T (nm_utils_fixup_vendor_string, "NEC Corp.", "NEC");
	T (nm_utils_fixup_vendor_string, "Netchip Technology, Inc.", "Netchip");
	T (nm_utils_fixup_vendor_string, "Netgear, Inc", "Netgear");
	T (nm_utils_fixup_vendor_string, "NetGear, Inc.", "NetGear");
	T (nm_utils_fixup_vendor_string, "Netgear", "Netgear");
	T (nm_utils_fixup_vendor_string, "Netopia, Inc.", "Netopia");
	T (nm_utils_fixup_vendor_string, "Netronome Systems, Inc.", "Netronome");
	T (nm_utils_fixup_vendor_string, "NetVin", "NetVin");
	T (nm_utils_fixup_vendor_string, "NetXen Incorporated", "NetXen");
	T (nm_utils_fixup_vendor_string, "Nordic Semiconductor ASA", "Nordic");
	T (nm_utils_fixup_vendor_string, "Northern Telecom", "Northern Telecom");
	T (nm_utils_fixup_vendor_string, "NovaTech", "NovaTech");
	T (nm_utils_fixup_vendor_string, "Novatel Wireless", "Novatel Wireless");
	T (nm_utils_fixup_vendor_string, "NVIDIA Corp.", "NVIDIA");
	T (nm_utils_fixup_vendor_string, "NVIDIA Corporation", "NVIDIA");
	T (nm_utils_fixup_vendor_string, "Olicom", "Olicom");
	T (nm_utils_fixup_vendor_string, "Olivetti Techcenter", "Olivetti");
	T (nm_utils_fixup_vendor_string, "Olympus Optical Co., Ltd", "Olympus");
	T (nm_utils_fixup_vendor_string, "OMEGA TECHNOLOGY", "OMEGA");
	T (nm_utils_fixup_vendor_string, "Omnidirectional Control Technology, Inc.", "Omnidirectional Control");
	T (nm_utils_fixup_vendor_string, "OpenMoko, Inc.", "OpenMoko");
	T (nm_utils_fixup_vendor_string, "Option", "Option");
	T (nm_utils_fixup_vendor_string, "OQO", "OQO");
	T (nm_utils_fixup_vendor_string, "Oracle/SUN", "Oracle");
	T (nm_utils_fixup_vendor_string, "Ovislink Corp.", "Ovislink");
	T (nm_utils_fixup_vendor_string, "Packet Engines Inc.", "Packet Engines");
	T (nm_utils_fixup_vendor_string, "Panasonic (Matsushita)", "Panasonic");
	T (nm_utils_fixup_vendor_string, "PEAK System", "PEAK System");
	T (nm_utils_fixup_vendor_string, "PEAK-System Technik GmbH", "PEAK-System");
	T (nm_utils_fixup_vendor_string, "PEGATRON CORPORATION", "PEGATRON CORPORATION");
	T (nm_utils_fixup_vendor_string, "Peppercon AG", "Peppercon");
	T (nm_utils_fixup_vendor_string, "Peracom Networks, Inc.", "Peracom");
	T (nm_utils_fixup_vendor_string, "Philips (or NXP)", "Philips");
	T (nm_utils_fixup_vendor_string, "Planex Communications, Inc", "Planex");
	T (nm_utils_fixup_vendor_string, "Planex Communications", "Planex");
	T (nm_utils_fixup_vendor_string, "Planex", "Planex");
	T (nm_utils_fixup_vendor_string, "PLANEX", "PLANEX");
	T (nm_utils_fixup_vendor_string, "Portsmith", "Portsmith");
	T (nm_utils_fixup_vendor_string, "Prolific Technology, Inc.", "Prolific");
	T (nm_utils_fixup_vendor_string, "Qcom", "Qcom");
	T (nm_utils_fixup_vendor_string, "Qi Hardware", "Qi");
	T (nm_utils_fixup_vendor_string, "QinHeng Electronics", "QinHeng");
	T (nm_utils_fixup_vendor_string, "QLogic Corp.", "QLogic");
	T (nm_utils_fixup_vendor_string, "Qualcomm Atheros Communications", "Qualcomm Atheros");
	T (nm_utils_fixup_vendor_string, "Qualcomm Atheros", "Qualcomm Atheros");
	T (nm_utils_fixup_vendor_string, "Qualcomm, Inc.", "Qualcomm");
	T (nm_utils_fixup_vendor_string, "Qualcomm / Option", "Qualcomm");
	T (nm_utils_fixup_vendor_string, "Quanta Computer, Inc.", "Quanta Computer");
	T (nm_utils_fixup_vendor_string, "Quanta Microsystems, Inc.", "Quanta");
	T (nm_utils_fixup_vendor_string, "Quantenna Communications, Inc.", "Quantenna");
	T (nm_utils_fixup_vendor_string, "RadioShack Corp. (Tandy)", "RadioShack");
	T (nm_utils_fixup_vendor_string, "Ralink corp.", "Ralink");
	T (nm_utils_fixup_vendor_string, "Ralink Technology, Corp.", "Ralink");
	T (nm_utils_fixup_vendor_string, "RDC Semiconductor, Inc.", "RDC");
	T (nm_utils_fixup_vendor_string, "Realtek Semiconductor Co., Ltd.", "Realtek");
	T (nm_utils_fixup_vendor_string, "Realtek Semiconductor Corp.", "Realtek");
	T (nm_utils_fixup_vendor_string, "Red Hat, Inc.", "Red Hat");
	T (nm_utils_fixup_vendor_string, "SafeNet (wrong ID)", "SafeNet");
	T (nm_utils_fixup_vendor_string, "Sagem", "Sagem");
	T (nm_utils_fixup_vendor_string, "Samsung Electronics Co., Ltd", "Samsung");
	T (nm_utils_fixup_vendor_string, "Sega Enterprises Ltd", "Sega");
	T (nm_utils_fixup_vendor_string, "Senao", "Senao");
	T (nm_utils_fixup_vendor_string, "Shark Multimedia", "Shark");
	T (nm_utils_fixup_vendor_string, "Sharp Corp.", "Sharp");
	T (nm_utils_fixup_vendor_string, "Siemens Information and Communication Products", "Siemens");
	T (nm_utils_fixup_vendor_string, "Sierra Wireless, Inc.", "Sierra Wireless");
	T (nm_utils_fixup_vendor_string, "Silicom", "Silicom");
	T (nm_utils_fixup_vendor_string, "Silicon Graphics Intl. Corp.", "Silicon Graphics");
	T (nm_utils_fixup_vendor_string, "Silicon Integrated Systems [SiS]", "SiS");
	T (nm_utils_fixup_vendor_string, "Sitecom Europe B.V.", "Sitecom");
	T (nm_utils_fixup_vendor_string, "Sitecom", "Sitecom");
	T (nm_utils_fixup_vendor_string, "smartBridges, Inc.", "smartBridges");
	T (nm_utils_fixup_vendor_string, "SohoWare", "SohoWare");
	T (nm_utils_fixup_vendor_string, "Solarflare Communications", "Solarflare");
	T (nm_utils_fixup_vendor_string, "Sony Corp.", "Sony");
	T (nm_utils_fixup_vendor_string, "SpeedStream", "SpeedStream");
	T (nm_utils_fixup_vendor_string, "Sphairon Access Systems GmbH", "Sphairon");
	T (nm_utils_fixup_vendor_string, "Standard Microsystems Corp [SMC]", "SMC");
	T (nm_utils_fixup_vendor_string, "Standard Microsystems Corp.", "Standard");
	T (nm_utils_fixup_vendor_string, "STMicroelectronics", "STMicroelectronics");
	T (nm_utils_fixup_vendor_string, "Sundance Technology Inc / IC Plus Corp", "Sundance");
	T (nm_utils_fixup_vendor_string, "Surecom Technology Corp.", "Surecom");
	T (nm_utils_fixup_vendor_string, "Surecom Technology", "Surecom");
	T (nm_utils_fixup_vendor_string, "Sweex", "Sweex");
	T (nm_utils_fixup_vendor_string, "SysKonnect", "SysKonnect");
	T (nm_utils_fixup_vendor_string, "T & A Mobile Phones", "T & A");
	T (nm_utils_fixup_vendor_string, "TDK Semiconductor Corp.", "TDK");
	T (nm_utils_fixup_vendor_string, "Tehuti Networks Ltd.", "Tehuti");
	T (nm_utils_fixup_vendor_string, "Tekram Technology Co., Ltd", "Tekram");
	T (nm_utils_fixup_vendor_string, "Telit Wireless Solutions", "Telit");
	T (nm_utils_fixup_vendor_string, "Texas Instruments, Inc.", "Texas");
	T (nm_utils_fixup_vendor_string, "Thales Norway A/S", "Thales");
	T (nm_utils_fixup_vendor_string, "TMT Technology, Inc.", "TMT");
	T (nm_utils_fixup_vendor_string, "Toshiba Corp.", "Toshiba");
	T (nm_utils_fixup_vendor_string, "TRENDnet", "TRENDnet");
	T (nm_utils_fixup_vendor_string, "Trident Microsystems", "Trident");
	T (nm_utils_fixup_vendor_string, "Trust International B.V.", "Trust");
	T (nm_utils_fixup_vendor_string, "TTTech Computertechnik AG (Wrong ID)", "TTTech");
	T (nm_utils_fixup_vendor_string, "TwinMOS", "TwinMOS");
	T (nm_utils_fixup_vendor_string, "U-Blox AG", "U-Blox");
	T (nm_utils_fixup_vendor_string, "ULi Electronics Inc.", "ULi");
	T (nm_utils_fixup_vendor_string, "U.S. Robotics", "U.S. Robotics");
	T (nm_utils_fixup_vendor_string, "Vaillant", "Vaillant");
	T (nm_utils_fixup_vendor_string, "VIA Technologies, Inc.", "VIA");
	T (nm_utils_fixup_vendor_string, "Victor Company of Japan, Ltd", "Victor");
	T (nm_utils_fixup_vendor_string, "VMware", "VMware");
	T (nm_utils_fixup_vendor_string, "VTech Holdings, Ltd", "VTech");
	T (nm_utils_fixup_vendor_string, "Wavecom", "Wavecom");
	T (nm_utils_fixup_vendor_string, "Westell", "Westell");
	T (nm_utils_fixup_vendor_string, "Western Digital Technologies, Inc.", "Western Digital");
	T (nm_utils_fixup_vendor_string, "Wilocity Ltd.", "Wilocity");
	T (nm_utils_fixup_vendor_string, "Winbond Electronics Corp", "Winbond");
	T (nm_utils_fixup_vendor_string, "Winbond", "Winbond");
	T (nm_utils_fixup_vendor_string, "Wistron NeWeb", "Wistron NeWeb");
	T (nm_utils_fixup_vendor_string, "Xircom", "Xircom");
	T (nm_utils_fixup_vendor_string, "Z-Com", "Z-Com");
	T (nm_utils_fixup_vendor_string, "Zinwell", "Zinwell");
	T (nm_utils_fixup_vendor_string, "Zoom Telephonics, Inc.", "Zoom");
	T (nm_utils_fixup_vendor_string, "ZTE WCDMA Technologies MSM", "ZTE");
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
