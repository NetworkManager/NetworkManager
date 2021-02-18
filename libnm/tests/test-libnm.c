/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm/nm-default-libnm.h"

#if defined(HAVE_DECL_MEMFD_CREATE) && HAVE_DECL_MEMFD_CREATE
    #include <linux/memfd.h>
#endif

#include <sys/mman.h>

#include "NetworkManager.h"
#include "nm-access-point.h"
#include "nm-checkpoint.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-dns-manager.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-libnm-utils.h"
#include "nm-object.h"
#include "nm-vpn-service-plugin.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

typedef struct {
    const char *desc;
    const char *expected;
    int         line;
} TestFixupData;

static void
_test_fixup_string(const TestFixupData *data, guint n_data, char *(*func)(const char *) )
{
    guint i;

    g_assert(data);
    g_assert(n_data > 0);
    g_assert(func);

    for (i = 0; i < n_data; i++, data++) {
        gs_free char *value = func(data->desc);

        if (!nm_streq0(value, data->expected)) {
            g_error("Error comparing value: %s:%i: expected %s%s%s for %s%s%s, but got %s%s%s",
                    __FILE__,
                    data->line,
                    NM_PRINT_FMT_QUOTE_STRING(data->expected),
                    NM_PRINT_FMT_QUOTE_STRING(data->desc),
                    NM_PRINT_FMT_QUOTE_STRING(value));
        }
    }
}

#define T_DATA(_desc, _expected)                                \
    {                                                           \
        .desc = _desc, .expected = _expected, .line = __LINE__, \
    }

static void
test_fixup_vendor_string(void)
{
    static const TestFixupData data[] = {
        T_DATA("3Com", "3Com"),
        T_DATA("3Com Corp.", "3Com"),
        T_DATA("3Com Corporation", "3Com"),
        T_DATA("Abocom Systems Inc", "Abocom"),
        T_DATA("AboCom Systems Inc", "AboCom"),
        T_DATA("Accton Technology Corp.", "Accton"),
        T_DATA("Accton Technology Corporation", "Accton"),
        T_DATA("Acer Communications & Multimedia", "Acer"),
        T_DATA("Actiontec Electronics, Inc. [hex]", "Actiontec"),
        T_DATA("Adaptec", "Adaptec"),
        T_DATA("Addtron Technology Co, Inc.", "Addtron"),
        T_DATA("ADMtek", "ADMtek"),
        T_DATA("ADMtek, Inc.", "ADMtek"),
        T_DATA("ADS Technologies, Inc.", "ADS"),
        T_DATA("Advanced Micro Devices, Inc. [AMD]", "AMD"),
        T_DATA("Advance Multimedia Internet Technology Inc. (AMIT)", "Advance"),
        T_DATA("AEI", "AEI"),
        T_DATA("Airprime, Incorporated", "Airprime"),
        T_DATA("AirTies Wireless Networks", "AirTies"),
        T_DATA("AirVast", "AirVast"),
        T_DATA("Alcatel Telecom", "Alcatel Telecom"),
        T_DATA("ALi Corp.", "ALi"),
        T_DATA("Allied Telesis", "Allied Telesis"),
        T_DATA("Allied Telesyn International", "Allied Telesyn"),
        T_DATA("Alteon Networks Inc.", "Alteon"),
        T_DATA("Altima (nee Broadcom)", "Altima"),
        T_DATA("A-Max Technology Macao Commercial Offshore Co. Ltd.", "A-Max"),
        T_DATA("Amigo Technology Inc.", "Amigo"),
        T_DATA("AMIT Technology, Inc.", "AMIT"),
        T_DATA("Anchor Chips, Inc.", "Anchor"),
        T_DATA("AnyDATA Corporation", "AnyDATA"),
        T_DATA("Apple Inc.", "Apple"),
        T_DATA("Apple, Inc.", "Apple"),
        T_DATA("ARC International", "ARC"),
        T_DATA("ASIX Electronics Corp.", "ASIX"),
        T_DATA("Asix Electronics Corporation", "Asix"),
        T_DATA("Askey Computer Corp. [hex]", "Askey"),
        T_DATA("ASUSTek Computer, Inc.", "ASUSTek Computer"),
        T_DATA("ASUSTek Computer, Inc. (wrong ID)", "ASUSTek Computer"),
        T_DATA("ATEN International Co., Ltd", "ATEN"),
        T_DATA("Atheros Communications", "Atheros"),
        T_DATA("Atheros Communications, Inc.", "Atheros"),
        T_DATA("AVM GmbH", "AVM"),
        T_DATA("AzureWave", "AzureWave"),
        T_DATA("Belkin", "Belkin"),
        T_DATA("Belkin Components", "Belkin"),
        T_DATA("Billionton Systems, Inc.", "Billionton"),
        T_DATA("Broadcom Corp.", "Broadcom"),
        T_DATA("Broadcom Limited", "Broadcom"),
        T_DATA("Brocade Communications Systems, Inc.", "Brocade"),
        T_DATA("BUFFALO INC. (formerly MelCo., Inc.)", "BUFFALO"),
        T_DATA("CACE Technologies Inc.", "CACE"),
        T_DATA("Cadence Design Systems, Inc.", "Cadence"),
        T_DATA("Chelsio Communications Inc", "Chelsio"),
        T_DATA("Chicony Electronics Co., Ltd", "Chicony"),
        T_DATA("Chu Yuen Enterprise Co., Ltd", "Chu Yuen"),
        T_DATA("Cisco Systems Inc", "Cisco"),
        T_DATA("Cisco Systems, Inc.", "Cisco"),
        T_DATA("CMOTECH Co., Ltd.", "CMOTECH"),
        T_DATA("CNet Technology Inc.", "CNet"),
        T_DATA("CNet Technology Inc", "CNet"),
        T_DATA("Comneon", "Comneon"),
        T_DATA("Compaq Computer Corp.", "Compaq"),
        T_DATA("Compaq Computer Corporation", "Compaq"),
        T_DATA("Compex", "Compex"),
        T_DATA("Computer Access Technology Corp.", "Computer Access"),
        T_DATA("Conexant Systems, Inc.", "Conexant"),
        T_DATA("Conexant Systems (Rockwell), Inc.", "Conexant"),
        T_DATA("Corega K.K.", "Corega K.K."),
        T_DATA("Curitel Communications, Inc.", "Curitel"),
        T_DATA("CyberTAN Technology", "CyberTAN"),
        T_DATA("Cypress Semiconductor Corp.", "Cypress"),
        T_DATA("Davicom Semiconductor, Inc.", "Davicom"),
        T_DATA("Dell Computer Corp.", "Dell"),
        T_DATA("DELTA Electronics, Inc", "DELTA"),
        T_DATA("Digital Equipment Corporation", "Digital Equipment"),
        T_DATA("D-Link Corp.", "D-Link"),
        T_DATA("D-Link System", "D-Link System"),
        T_DATA("D-Link System Inc", "D-Link System"),
        T_DATA("DrayTek Corp.", "DrayTek"),
        T_DATA("d'TV", "d'TV"),
        T_DATA("DVICO", "DVICO"),
        T_DATA("Edimax Computer Co.", "Edimax"),
        T_DATA("Edimax Technology Co., Ltd", "Edimax"),
        T_DATA("Efar Microsystems", "Efar"),
        T_DATA("Efficient Networks, Inc.", "Efficient"),
        T_DATA("ELCON Systemtechnik", "ELCON"),
        T_DATA("Elecom Co., Ltd", "Elecom"),
        T_DATA("ELSA AG", "ELSA"),
        T_DATA("Emulex Corporation", "Emulex"),
        T_DATA("Encore Electronics Inc.", "Encore"),
        T_DATA("EndPoints, Inc.", "EndPoints"),
        T_DATA("Entrega [hex]", "Entrega"),
        T_DATA("Ericsson Business Mobile Networks BV", "Ericsson"),
        T_DATA("eTEK Labs", "eTEK"),
        T_DATA("Exar Corp.", "Exar"),
        T_DATA("Fiberline", "Fiberline"),
        T_DATA("Fujitsu Limited.", "Fujitsu"),
        T_DATA("Fujitsu Siemens Computers", "Fujitsu Siemens"),
        T_DATA("Gateway, Inc.", "Gateway"),
        T_DATA("Gemtek", "Gemtek"),
        T_DATA("Genesys Logic, Inc.", "Genesys Logic"),
        T_DATA("Global Sun Technology", "Global Sun"),
        T_DATA("Global Sun Technology, Inc.", "Global Sun"),
        T_DATA("GlobeSpan, Inc.", "GlobeSpan"),
        T_DATA("Gmate, Inc.", "Gmate"),
        T_DATA("Good Way Technology", "Good Way"),
        T_DATA("Guillemot Corp.", "Guillemot"),
        T_DATA("Hangzhou Silan Microelectronics Co., Ltd.", "Hangzhou Silan"),
        T_DATA("Hawking Technologies", "Hawking"),
        T_DATA("Hewlett-Packard", "Hewlett-Packard"),
        T_DATA("Hirose Electric", "Hirose Electric"),
        T_DATA("Holtek Microelectronics Inc", "Holtek"),
        T_DATA("Huawei-3Com", "Huawei-3Com"),
        T_DATA("Huawei Technologies Co., Ltd.", "Huawei"),
        T_DATA("ICS Advent", "ICS Advent"),
        T_DATA("IMC Networks", "IMC"),
        T_DATA("Intel Corp.", "Intel"),
        T_DATA("Intel Corporation", "Intel"),
        T_DATA("Intellon Corp.", "Intellon"),
        T_DATA("InterBiometrics", "InterBiometrics"),
        T_DATA("Intersil Corp.", "Intersil"),
        T_DATA("Intersil Corporation", "Intersil"),
        T_DATA("I-O Data Device, Inc.", "I-O Data Device"),
        T_DATA("Jaton Corp.", "Jaton"),
        T_DATA("JMicron Technology Corp.", "JMicron"),
        T_DATA("Kawasaki LSI", "Kawasaki LSI"),
        T_DATA("KC Technology, Inc.", "KC"),
        T_DATA("Kingston Technology", "Kingston"),
        T_DATA("KTI", "KTI"),
        T_DATA("Kvaser AB", "Kvaser"),
        T_DATA("LapLink, Inc.", "LapLink"),
        T_DATA("Lenovo", "Lenovo"),
        T_DATA("LevelOne", "LevelOne"),
        T_DATA("LG Electronics, Inc.", "LG"),
        T_DATA("LG Electronics USA, Inc.", "LG"),
        T_DATA("Linksys, Inc.", "Linksys"),
        T_DATA("Linksys (?)", "Linksys"),
        T_DATA("Linksys", "Linksys"),
        T_DATA("Lite-On Communications Inc", "Lite-On"),
        T_DATA("Lite-On Technology Corp.", "Lite-On"),
        T_DATA("Logitec Corp.", "Logitec"),
        T_DATA("Logitech, Inc.", "Logitech"),
        T_DATA("LSI Corporation", "LSI"),
        T_DATA("LSI Logic / Symbios Logic", "LSI Logic"),
        T_DATA("Macronix, Inc. [MXIC]", "MXIC"),
        T_DATA("Marvell Semiconductor, Inc.", "Marvell"),
        T_DATA("Marvell Technology Group Ltd.", "Marvell"),
        T_DATA("MediaTek Inc.", "MediaTek"),
        T_DATA("Mellanox Technologies", "Mellanox"),
        T_DATA("Memorex", "Memorex"),
        T_DATA("Micrel-Kendin", "Micrel-Kendin"),
        T_DATA("Microchip Technology, Inc.", "Microchip"),
        T_DATA("Microcomputer Systems (M) Son", "Microcomputer"),
        T_DATA("Microsoft Corp.", "Microsoft"),
        T_DATA("Microsoft Corporation", "Microsoft"),
        T_DATA("Micro-Star International Co., Ltd. [MSI]", "MSI"),
        T_DATA("Micro Star International", "Micro Star"),
        T_DATA("Mobility", "Mobility"),
        T_DATA("MosChip Semiconductor", "MosChip"),
        T_DATA("Motorola PCS", "Motorola"),
        T_DATA("MYRICOM Inc.", "MYRICOM"),
        T_DATA("MYSON Technology Inc", "MYSON"),
        T_DATA("National Instruments Corp.", "National"),
        T_DATA("National Semiconductor Corporation", "National"),
        T_DATA("NEC Corp.", "NEC"),
        T_DATA("Netchip Technology, Inc.", "Netchip"),
        T_DATA("Netgear, Inc", "Netgear"),
        T_DATA("NetGear, Inc.", "NetGear"),
        T_DATA("Netgear", "Netgear"),
        T_DATA("Netopia, Inc.", "Netopia"),
        T_DATA("Netronome Systems, Inc.", "Netronome"),
        T_DATA("NetVin", "NetVin"),
        T_DATA("NetXen Incorporated", "NetXen"),
        T_DATA("Nordic Semiconductor ASA", "Nordic"),
        T_DATA("Northern Telecom", "Northern Telecom"),
        T_DATA("NovaTech", "NovaTech"),
        T_DATA("Novatel Wireless", "Novatel Wireless"),
        T_DATA("NVIDIA Corp.", "NVIDIA"),
        T_DATA("NVIDIA Corporation", "NVIDIA"),
        T_DATA("Olicom", "Olicom"),
        T_DATA("Olivetti Techcenter", "Olivetti"),
        T_DATA("Olympus Optical Co., Ltd", "Olympus"),
        T_DATA("OMEGA TECHNOLOGY", "OMEGA"),
        T_DATA("Omnidirectional Control Technology, Inc.", "Omnidirectional Control"),
        T_DATA("OpenMoko, Inc.", "OpenMoko"),
        T_DATA("Option", "Option"),
        T_DATA("OQO", "OQO"),
        T_DATA("Oracle/SUN", "Oracle"),
        T_DATA("Ovislink Corp.", "Ovislink"),
        T_DATA("Packet Engines Inc.", "Packet Engines"),
        T_DATA("Panasonic (Matsushita)", "Panasonic"),
        T_DATA("PEAK System", "PEAK System"),
        T_DATA("PEAK-System Technik GmbH", "PEAK-System"),
        T_DATA("PEGATRON CORPORATION", "PEGATRON CORPORATION"),
        T_DATA("Peppercon AG", "Peppercon"),
        T_DATA("Peracom Networks, Inc.", "Peracom"),
        T_DATA("Philips (or NXP)", "Philips"),
        T_DATA("Planex Communications, Inc", "Planex"),
        T_DATA("Planex Communications", "Planex"),
        T_DATA("Planex", "Planex"),
        T_DATA("PLANEX", "PLANEX"),
        T_DATA("Portsmith", "Portsmith"),
        T_DATA("Prolific Technology, Inc.", "Prolific"),
        T_DATA("Qcom", "Qcom"),
        T_DATA("Qi Hardware", "Qi"),
        T_DATA("QinHeng Electronics", "QinHeng"),
        T_DATA("QLogic Corp.", "QLogic"),
        T_DATA("Qualcomm Atheros Communications", "Qualcomm Atheros"),
        T_DATA("Qualcomm Atheros", "Qualcomm Atheros"),
        T_DATA("Qualcomm, Inc.", "Qualcomm"),
        T_DATA("Qualcomm / Option", "Qualcomm"),
        T_DATA("Quanta Computer, Inc.", "Quanta Computer"),
        T_DATA("Quanta Microsystems, Inc.", "Quanta"),
        T_DATA("Quantenna Communications, Inc.", "Quantenna"),
        T_DATA("RadioShack Corp. (Tandy)", "RadioShack"),
        T_DATA("Ralink corp.", "Ralink"),
        T_DATA("Ralink Technology, Corp.", "Ralink"),
        T_DATA("RDC Semiconductor, Inc.", "RDC"),
        T_DATA("Realtek Semiconductor Co., Ltd.", "Realtek"),
        T_DATA("Realtek Semiconductor Corp.", "Realtek"),
        T_DATA("Red Hat, Inc.", "Red Hat"),
        T_DATA("SafeNet (wrong ID)", "SafeNet"),
        T_DATA("Sagem", "Sagem"),
        T_DATA("Samsung Electronics Co., Ltd", "Samsung"),
        T_DATA("Sega Enterprises Ltd", "Sega"),
        T_DATA("Senao", "Senao"),
        T_DATA("Shark Multimedia", "Shark"),
        T_DATA("Sharp Corp.", "Sharp"),
        T_DATA("Siemens Information and Communication Products", "Siemens"),
        T_DATA("Sierra Wireless, Inc.", "Sierra Wireless"),
        T_DATA("Silicom", "Silicom"),
        T_DATA("Silicon Graphics Intl. Corp.", "Silicon Graphics"),
        T_DATA("Silicon Integrated Systems [SiS]", "SiS"),
        T_DATA("Sitecom Europe B.V.", "Sitecom"),
        T_DATA("Sitecom", "Sitecom"),
        T_DATA("smartBridges, Inc.", "smartBridges"),
        T_DATA("SohoWare", "SohoWare"),
        T_DATA("Solarflare Communications", "Solarflare"),
        T_DATA("Sony Corp.", "Sony"),
        T_DATA("SpeedStream", "SpeedStream"),
        T_DATA("Sphairon Access Systems GmbH", "Sphairon"),
        T_DATA("Standard Microsystems Corp [SMC]", "SMC"),
        T_DATA("Standard Microsystems Corp.", "Standard"),
        T_DATA("STMicroelectronics", "STMicroelectronics"),
        T_DATA("Sundance Technology Inc / IC Plus Corp", "Sundance"),
        T_DATA("Surecom Technology Corp.", "Surecom"),
        T_DATA("Surecom Technology", "Surecom"),
        T_DATA("Sweex", "Sweex"),
        T_DATA("SysKonnect", "SysKonnect"),
        T_DATA("T & A Mobile Phones", "T & A"),
        T_DATA("TDK Semiconductor Corp.", "TDK"),
        T_DATA("Tehuti Networks Ltd.", "Tehuti"),
        T_DATA("Tekram Technology Co., Ltd", "Tekram"),
        T_DATA("Telit Wireless Solutions", "Telit"),
        T_DATA("Texas Instruments, Inc.", "Texas"),
        T_DATA("Thales Norway A/S", "Thales"),
        T_DATA("TMT Technology, Inc.", "TMT"),
        T_DATA("Toshiba Corp.", "Toshiba"),
        T_DATA("TRENDnet", "TRENDnet"),
        T_DATA("Trident Microsystems", "Trident"),
        T_DATA("Trust International B.V.", "Trust"),
        T_DATA("TTTech Computertechnik AG (Wrong ID)", "TTTech"),
        T_DATA("TwinMOS", "TwinMOS"),
        T_DATA("U-Blox AG", "U-Blox"),
        T_DATA("ULi Electronics Inc.", "ULi"),
        T_DATA("U.S. Robotics", "U.S. Robotics"),
        T_DATA("Vaillant", "Vaillant"),
        T_DATA("VIA Technologies, Inc.", "VIA"),
        T_DATA("Victor Company of Japan, Ltd", "Victor"),
        T_DATA("VMware", "VMware"),
        T_DATA("VTech Holdings, Ltd", "VTech"),
        T_DATA("Wavecom", "Wavecom"),
        T_DATA("Westell", "Westell"),
        T_DATA("Western Digital Technologies, Inc.", "Western Digital"),
        T_DATA("Wilocity Ltd.", "Wilocity"),
        T_DATA("Winbond Electronics Corp", "Winbond"),
        T_DATA("Winbond", "Winbond"),
        T_DATA("Wistron NeWeb", "Wistron NeWeb"),
        T_DATA("Xircom", "Xircom"),
        T_DATA("Z-Com", "Z-Com"),
        T_DATA("Zinwell", "Zinwell"),
        T_DATA("Zoom Telephonics, Inc.", "Zoom"),
        T_DATA("ZTE WCDMA Technologies MSM", "ZTE"),
        T_DATA("ZyDAS", "ZyDAS"),
        T_DATA("ZyXEL Communications Corp.", "ZyXEL"),
    };

    _test_fixup_string(data, G_N_ELEMENTS(data), nm_utils_fixup_vendor_string);
}

static void
test_fixup_product_string(void)
{
    static const TestFixupData data[] = {
        T_DATA("10/100BaseTX [RTL81xx]", "RTL81xx"),
        T_DATA("10/100 Ethernet", NULL),
        T_DATA("10/100 Ethernet [pegasus]", "pegasus"),
        T_DATA("10/100 USB Ethernet", NULL),
        T_DATA("10/100 USB NIC", NULL),
        T_DATA("1010/1020/1007/1741 10Gbps CNA", "1010/1020/1007/1741"),
        T_DATA("1012 PCMCIA 10/100 Ethernet Card [RTL81xx]", "1012"),
        T_DATA("101 Ethernet [klsi]", "101"),
        T_DATA("10GbE Converged Network Adapter (TCP/IP Networking)", NULL),
        T_DATA("10GbE Ethernet Adapter", NULL),
        T_DATA("10 Gigabit BR KX4 Dual Port Network Connection", "BR KX4"),
        T_DATA("10-Giga TOE SmartNIC 2-Port", "SmartNIC"),
        T_DATA("10-Giga TOE SmartNIC", "SmartNIC"),
        T_DATA("10Mbps Ethernet [klsi]", "klsi"),
        T_DATA("1860 16Gbps/10Gbps Fabric Adapter", "1860"),
        T_DATA("190 Ethernet Adapter", "190"),
        T_DATA("191 Gigabit Ethernet Adapter", "191"),
        T_DATA("21145 Fast Ethernet", "21145"),
        T_DATA("21x4x DEC-Tulip compatible 10/100 Ethernet", "21x4x"),
        T_DATA("21x4x DEC-Tulip compatible Fast Ethernet", "21x4x"),
        T_DATA("2202 Ethernet [klsi]", "2202"),
        T_DATA("2202 Ethernet [pegasus]", "2202"),
        T_DATA("3C19250 Ethernet [klsi]", "3C19250"),
        T_DATA("3c450 HomePNA [Tornado]", "3c450 HomePNA"),
        T_DATA("3C460B 10/100 Ethernet Adapter", "3C460B"),
        T_DATA("3c555 Laptop Hurricane", "3c555 Hurricane"),
        T_DATA("3c556B CardBus [Tornado]", "3c556B"),
        T_DATA("3c556 Hurricane CardBus [Cyclone]", "3c556 Hurricane"),
        T_DATA("3c575 Megahertz 10/100 LAN CardBus [Boomerang]", "3c575 Megahertz"),
        T_DATA("3c590 10BaseT [Vortex]", "3c590"),
        T_DATA("3c592 EISA 10mbps Demon/Vortex", "3c592 Demon/Vortex"),
        T_DATA("3c595 100Base-MII [Vortex]", "3c595"),
        T_DATA("3c595 100BaseT4 [Vortex]", "3c595"),
        T_DATA("3c595 100BaseTX [Vortex]", "3c595"),
        T_DATA("3c595 Megahertz 10/100 LAN CardBus [Boomerang]", "3c595 Megahertz"),
        T_DATA("3c597 EISA Fast Demon/Vortex", "3c597 Fast Demon/Vortex"),
        T_DATA("3c900 10BaseT [Boomerang]", "3c900"),
        T_DATA("3c900 10Mbps Combo [Boomerang]", "3c900 Combo"),
        T_DATA("3c900B-Combo Etherlink XL [Cyclone]", "3c900B-Combo Etherlink XL"),
        T_DATA("3c900B-FL 10base-FL [Cyclone]", "3c900B-FL"),
        T_DATA("3c900B-TPC Etherlink XL [Cyclone]", "3c900B-TPC Etherlink XL"),
        T_DATA("3c900B-TPO Etherlink XL [Cyclone]", "3c900B-TPO Etherlink XL"),
        T_DATA("3c905 100BaseT4 [Boomerang]", "3c905"),
        T_DATA("3c905 100BaseTX [Boomerang]", "3c905"),
        T_DATA("3c905B 100BaseTX [Cyclone]", "3c905B"),
        T_DATA("3c905B Deluxe Etherlink 10/100/BNC [Cyclone]", "3c905B Deluxe Etherlink"),
        T_DATA("3c905B-FX Fast Etherlink XL FX 100baseFx [Cyclone]",
               "3c905B-FX Fast Etherlink XL FX"),
        T_DATA("3c905B-T4 Fast EtherLink XL [Cyclone]", "3c905B-T4 Fast EtherLink XL"),
        T_DATA("3C905B-TX Fast Etherlink XL PCI", "3C905B-TX Fast Etherlink XL"),
        T_DATA("3c905C-TX/TX-M [Tornado]", "3c905C-TX/TX-M"),
        T_DATA("3C920B-EMB Integrated Fast Ethernet Controller [Tornado]", "3C920B-EMB"),
        T_DATA("3C920B-EMB-WNM Integrated Fast Ethernet Controller", "3C920B-EMB-WNM"),
        T_DATA("3c940 10/100/1000Base-T [Marvell]", "3c940"),
        T_DATA("3c940B 10/100/1000Base-T", "3c940B"),
        T_DATA("3c980-C 10/100baseTX NIC [Python-T]", "3c980-C"),
        T_DATA("3c980-TX Fast Etherlink XL Server Adapter [Cyclone]", "3c980-TX Fast Etherlink XL"),
        T_DATA("3c982-TXM 10/100baseTX Dual Port A [Hydra]", "3c982-TXM A"),
        T_DATA("3c982-TXM 10/100baseTX Dual Port B [Hydra]", "3c982-TXM B"),
        T_DATA("3c985 1000BaseSX (SX/TX)", "3c985"),
        T_DATA("3C990B-TX-M/3C990BSVR [Typhoon2]", "3C990B-TX-M/3C990BSVR"),
        T_DATA("3C990SVR [Typhoon Server]", "3C990SVR"),
        T_DATA("3C990-TX [Typhoon]", "3C990-TX"),
        T_DATA("3cCFE575BT Megahertz 10/100 LAN CardBus [Cyclone]", "3cCFE575BT Megahertz"),
        T_DATA("3cCFE575CT CardBus [Cyclone]", "3cCFE575CT"),
        T_DATA("3cCFE656 CardBus [Cyclone]", "3cCFE656"),
        T_DATA("3cCFEM656B 10/100 LAN+Winmodem CardBus [Cyclone]", "3cCFEM656B"),
        T_DATA("3Com 3C920B-EMB-WNM Integrated Fast Ethernet Controller", "3Com 3C920B-EMB-WNM"),
        T_DATA("3Com 3CRUSBN275 802.11abgn Wireless Adapter [Atheros AR9170]", "3Com 3CRUSBN275"),
        T_DATA("3com 3CRWE154G72 [Office Connect Wireless LAN Adapter]", "3com 3CRWE154G72"),
        T_DATA("3CR990-FX-95/97/95 [Typhon Fiber]", "3CR990-FX-95/97/95"),
        T_DATA("3CR990SVR95 [Typhoon Server 56-bit]", "3CR990SVR95"),
        T_DATA("3CR990SVR97 [Typhoon Server 168-bit]", "3CR990SVR97"),
        T_DATA("3CR990-TX-95 [Typhoon 56-bit]", "3CR990-TX-95"),
        T_DATA("3CR990-TX-97 [Typhoon 168-bit]", "3CR990-TX-97"),
        T_DATA("3CRPAG175 Wireless PC Card", "3CRPAG175"),
        T_DATA("3CRUSB10075 802.11bg [ZyDAS ZD1211]", "3CRUSB10075"),
        T_DATA("3CRWE254G72 802.11g Adapter", "3CRWE254G72"),
        T_DATA("3CSOHO100B-TX 910-A01 [tulip]", "3CSOHO100B-TX 910-A01"),
        T_DATA("3cSOHO100-TX Hurricane", "3cSOHO100-TX Hurricane"),
        T_DATA("3cXFEM656C 10/100 LAN+Winmodem CardBus [Tornado]", "3cXFEM656C"),
        T_DATA("4410a Wireless-G Adapter [Intersil ISL3887]", "4410a"),
        T_DATA("4DWave DX", "4DWave DX"),
        T_DATA("4G LTE adapter", NULL),
        T_DATA("54g USB Network Adapter", NULL),
        T_DATA("570x 10/100 Integrated Controller", "570x"),
        T_DATA("79c970 [PCnet32 LANCE]", "79c970"),
        T_DATA("79c978 [HomePNA]", "79c978"),
        T_DATA("80003ES2LAN Gigabit Ethernet Controller (Copper)", "80003ES2LAN"),
        T_DATA("80003ES2LAN Gigabit Ethernet Controller (Serdes)", "80003ES2LAN"),
        T_DATA("802.11a/b/g/n USB Wireless LAN Card", NULL),
        T_DATA("802.11 Adapter", NULL),
        T_DATA("802.11bgn 1T1R Mini Card Wireless Adapter", "1T1R"),
        T_DATA("802.11bg", NULL),
        T_DATA("802.11b/g/n USB Wireless LAN Card", NULL),
        T_DATA("802.11b/g/n USB Wireless Network Adapter", NULL),
        T_DATA("802.11b/g/n Wireless Network Adapter", NULL),
        T_DATA("802.11b/g Turbo Wireless Adapter", NULL),
        T_DATA("802.11b/g Wireless Network Adapter", NULL),
        T_DATA("802.11g Wireless Adapter [Intersil ISL3886]", "Intersil ISL3886"),
        T_DATA("802.11n adapter", NULL),
        T_DATA("802.11n/b/g Mini Wireless LAN USB2.0 Adapter", NULL),
        T_DATA("802.11n/b/g Wireless LAN USB2.0 Adapter", NULL),
        T_DATA("802.11 n/g/b Wireless LAN Adapter", NULL),
        T_DATA("802.11 n/g/b Wireless LAN USB Adapter", NULL),
        T_DATA("802.11 n/g/b Wireless LAN USB Mini-Card", NULL),
        T_DATA("802.11n Network Adapter", NULL),
        T_DATA("802.11n Network Adapter (wrong ID - swapped vendor and device)", NULL),
        T_DATA("802.11n USB Wireless Card", NULL),
        T_DATA("802.11n Wireless Adapter", NULL),
        T_DATA("802.11n Wireless LAN Card", NULL),
        T_DATA("802.11n Wireless USB Card", NULL),
        T_DATA("802AIN Wireless N Network Adapter [Atheros AR9170+AR9101]",
               "Atheros AR9170+AR9101"),
        T_DATA("802UIG-1 802.11g Wireless Mini Adapter [Intersil ISL3887]", "Intersil ISL3887"),
        T_DATA("82540EM Gigabit Ethernet Controller", "82540EM"),
        T_DATA("82540EM Gigabit Ethernet Controller (LOM)", "82540EM"),
        T_DATA("82540EP Gigabit Ethernet Controller", "82540EP"),
        T_DATA("82540EP Gigabit Ethernet Controller (Mobile)", "82540EP"),
        T_DATA("82541EI Gigabit Ethernet Controller", "82541EI"),
        T_DATA("82541ER Gigabit Ethernet Controller", "82541ER"),
        T_DATA("82541GI Gigabit Ethernet Controller", "82541GI"),
        T_DATA("82541PI Gigabit Ethernet Controller", "82541PI"),
        T_DATA("82542 Gigabit Ethernet Controller (Fiber)", "82542"),
        T_DATA("82543GC Gigabit Ethernet Controller (Copper)", "82543GC"),
        T_DATA("82543GC Gigabit Ethernet Controller (Fiber)", "82543GC"),
        T_DATA("82544EI Gigabit Ethernet Controller (Copper)", "82544EI"),
        T_DATA("82544EI Gigabit Ethernet Controller (Fiber)", "82544EI"),
        T_DATA("82544GC Gigabit Ethernet Controller (Copper)", "82544GC"),
        T_DATA("82544GC Gigabit Ethernet Controller (LOM)", "82544GC"),
        T_DATA("82545EM Gigabit Ethernet Controller (Copper)", "82545EM"),
        T_DATA("82545EM Gigabit Ethernet Controller (Fiber)", "82545EM"),
        T_DATA("82545GM Gigabit Ethernet Controller", "82545GM"),
        T_DATA("82546EB Gigabit Ethernet Controller", "82546EB"),
        T_DATA("82546EB Gigabit Ethernet Controller (Copper)", "82546EB"),
        T_DATA("82546EB Gigabit Ethernet Controller (Fiber)", "82546EB"),
        T_DATA("82546GB Gigabit Ethernet Controller", "82546GB"),
        T_DATA("82546GB Gigabit Ethernet Controller (Copper)", "82546GB"),
        T_DATA("82547EI Gigabit Ethernet Controller", "82547EI"),
        T_DATA("82547EI Gigabit Ethernet Controller (Mobile)", "82547EI"),
        T_DATA("82547GI Gigabit Ethernet Controller", "82547GI"),
        T_DATA("82551QM Ethernet Controller", "82551QM"),
        T_DATA("82552 10/100 Network Connection", "82552"),
        T_DATA("82557/8/9/0/1 Ethernet Pro 100", "82557/8/9/0/1"),
        T_DATA("82559 Ethernet Controller", "82559"),
        T_DATA("82559 InBusiness 10/100", "82559 InBusiness"),
        T_DATA("8255xER/82551IT Fast Ethernet Controller", "8255xER/82551IT"),
        T_DATA("82562 EM/EX/GX - PRO/100 VM Ethernet Controller", "82562 EM/EX/GX"),
        T_DATA("82562 EM/EX/GX - PRO/100 VM (LOM) Ethernet Controller", "82562 EM/EX/GX"),
        T_DATA("82562EM/EX/GX - PRO/100 VM (LOM) Ethernet Controller Mobile", "82562EM/EX/GX"),
        T_DATA("82562ET/EZ/GT/GZ - PRO/100 VE Ethernet Controller", "82562ET/EZ/GT/GZ"),
        T_DATA("82562ET/EZ/GT/GZ - PRO/100 VE (LOM) Ethernet Controller", "82562ET/EZ/GT/GZ"),
        T_DATA("82562ET/EZ/GT/GZ - PRO/100 VE (LOM) Ethernet Controller Mobile",
               "82562ET/EZ/GT/GZ"),
        T_DATA("82562EZ 10/100 Ethernet Controller", "82562EZ"),
        T_DATA("82562G 10/100 Network Connection", "82562G"),
        T_DATA("82562G-2 10/100 Network Connection", "82562G-2"),
        T_DATA("82562G - PRO/100 VE Ethernet Controller Mobile", "82562G"),
        T_DATA("82562G - PRO/100 VE (LOM) Ethernet Controller", "82562G"),
        T_DATA("82562GT 10/100 Network Connection", "82562GT"),
        T_DATA("82562GT-2 10/100 Network Connection", "82562GT-2"),
        T_DATA("82562V 10/100 Network Connection", "82562V"),
        T_DATA("82562V-2 10/100 Network Connection", "82562V-2"),
        T_DATA("82566DC-2 Gigabit Network Connection", "82566DC-2"),
        T_DATA("82566DC Gigabit Network Connection", "82566DC"),
        T_DATA("82566DM-2 Gigabit Network Connection", "82566DM-2"),
        T_DATA("82566DM Gigabit Network Connection", "82566DM"),
        T_DATA("82566MC Gigabit Network Connection", "82566MC"),
        T_DATA("82566MM Gigabit Network Connection", "82566MM"),
        T_DATA("82567LF-2 Gigabit Network Connection", "82567LF-2"),
        T_DATA("82567LF-3 Gigabit Network Connection", "82567LF-3"),
        T_DATA("82567LF Gigabit Network Connection", "82567LF"),
        T_DATA("82567LM-2 Gigabit Network Connection", "82567LM-2"),
        T_DATA("82567LM-3 Gigabit Network Connection", "82567LM-3"),
        T_DATA("82567LM-4 Gigabit Network Connection", "82567LM-4"),
        T_DATA("82567LM Gigabit Network Connection", "82567LM"),
        T_DATA("82567V-2 Gigabit Network Connection", "82567V-2"),
        T_DATA("82567V-3 Gigabit Network Connection", "82567V-3"),
        T_DATA("82567V-4 Gigabit Network Connection", "82567V-4"),
        T_DATA("82567V Gigabit Network Connection", "82567V"),
        T_DATA("82571EB Dual Port Gigabit Mezzanine Adapter", "82571EB Mezzanine"),
        T_DATA("82571EB Gigabit Ethernet Controller", "82571EB"),
        T_DATA("82571EB Gigabit Ethernet Controller (Copper)", "82571EB"),
        T_DATA("82571EB Gigabit Ethernet Controller (Fiber)", "82571EB"),
        T_DATA("82571EB Quad Port Gigabit Mezzanine Adapter", "82571EB Quad Port Mezzanine"),
        T_DATA("82571PT Gigabit PT Quad Port Server ExpressModule", "82571PT PT Quad Port"),
        T_DATA("82572EI Gigabit Ethernet Controller", "82572EI"),
        T_DATA("82572EI Gigabit Ethernet Controller (Copper)", "82572EI"),
        T_DATA("82572EI Gigabit Ethernet Controller (Fiber)", "82572EI"),
        T_DATA("82573E Gigabit Ethernet Controller (Copper)", "82573E"),
        T_DATA("82573L Gigabit Ethernet Controller", "82573L"),
        T_DATA("82573V Gigabit Ethernet Controller (Copper)", "82573V"),
        T_DATA("82574L Gigabit Network Connection", "82574L"),
        T_DATA("82575EB Gigabit Backplane Connection", "82575EB Backplane Connection"),
        T_DATA("82575EB Gigabit Network Connection", "82575EB"),
        T_DATA("82575GB Gigabit Network Connection", "82575GB"),
        T_DATA("82576 Gigabit Backplane Connection", "82576 Backplane Connection"),
        T_DATA("82576 Gigabit Network Connection", "82576"),
        T_DATA("82576NS Gigabit Network Connection", "82576NS"),
        T_DATA("82576NS SerDes Gigabit Network Connection", "82576NS SerDes"),
        T_DATA("82576 Virtual Function", "82576 Virtual Function"),
        T_DATA("82577LC Gigabit Network Connection", "82577LC"),
        T_DATA("82577LM Gigabit Network Connection", "82577LM"),
        T_DATA("82578DC Gigabit Network Connection", "82578DC"),
        T_DATA("82578DM Gigabit Network Connection", "82578DM"),
        T_DATA("82579LM Gigabit Network Connection (Lewisville)", "82579LM"),
        T_DATA("82579V Gigabit Network Connection", "82579V"),
        T_DATA("82580 Gigabit Backplane Connection", "82580 Backplane Connection"),
        T_DATA("82580 Gigabit Fiber Network Connection", "82580"),
        T_DATA("82580 Gigabit Network Connection", "82580"),
        T_DATA("82580 Gigabit SFP Connection", "82580 SFP Connection"),
        T_DATA("82583V Gigabit Network Connection", "82583V"),
        T_DATA("82597EX 10GbE Ethernet Controller", "82597EX"),
        T_DATA("82598 10GbE PCI-Express Ethernet Controller", "82598"),
        T_DATA("82598EB 10-Gigabit AF Dual Port Network Connection", "82598EB AF"),
        T_DATA("82598EB 10-Gigabit AF Network Connection", "82598EB AF"),
        T_DATA("82598EB 10-Gigabit AT2 Server Adapter", "82598EB AT2"),
        T_DATA("82598EB 10-Gigabit AT CX4 Network Connection", "82598EB AT CX4"),
        T_DATA("82598EB 10-Gigabit AT Network Connection", "82598EB AT"),
        T_DATA("82598EB 10-Gigabit Dual Port Network Connection", "82598EB"),
        T_DATA("82598EB Gigabit BX Network Connection", "82598EB BX"),
        T_DATA("82599 10 Gigabit Dual Port Backplane Connection", "82599 Backplane Connection"),
        T_DATA("82599 10 Gigabit Dual Port Backplane Connection with FCoE",
               "82599 Backplane Connection with FCoE"),
        T_DATA("82599 10 Gigabit Dual Port Network Connection", "82599"),
        T_DATA("82599 10 Gigabit Dual Port Network Connection with FCoE", "82599 with FCoE"),
        T_DATA("82599 10 Gigabit Network Connection", "82599"),
        T_DATA("82599 10 Gigabit TN Network Connection", "82599 TN"),
        T_DATA("82599ES 10 Gigabit Network Connection", "82599ES"),
        T_DATA("82599ES 10-Gigabit SFI/SFP+ Network Connection", "82599ES SFI/SFP+"),
        T_DATA("82599 Ethernet Controller Virtual Function", "82599 Virtual Function"),
        T_DATA("82599 Virtual Function", "82599 Virtual Function"),
        T_DATA("82801BA/BAM/CA/CAM Ethernet Controller", "82801BA/BAM/CA/CAM"),
        T_DATA("82801CAM (ICH3) PRO/100 VE Ethernet Controller", "82801CAM"),
        T_DATA("82801CAM (ICH3) PRO/100 VE (LOM) Ethernet Controller", "82801CAM"),
        T_DATA("82801CAM (ICH3) PRO/100 VM Ethernet Controller", "82801CAM"),
        T_DATA("82801CAM (ICH3) PRO/100 VM (KM) Ethernet Controller", "82801CAM"),
        T_DATA("82801CAM (ICH3) PRO/100 VM (LOM) Ethernet Controller", "82801CAM"),
        T_DATA("82801DB PRO/100 VE (CNR) Ethernet Controller", "82801DB PRO/100 VE"),
        T_DATA("82801DB PRO/100 VE (LOM) Ethernet Controller", "82801DB PRO/100 VE"),
        T_DATA("82801DB PRO/100 VE (MOB) Ethernet Controller", "82801DB PRO/100 VE"),
        T_DATA("82801DB PRO/100 VM (CNR) Ethernet Controller", "82801DB PRO/100 VM"),
        T_DATA("82801DB PRO/100 VM (LOM) Ethernet Controller", "82801DB PRO/100 VM"),
        T_DATA("82801DB PRO/100 VM (MOB) Ethernet Controller", "82801DB PRO/100 VM"),
        T_DATA("82801EB/ER (ICH5/ICH5R) integrated LAN Controller", "82801EB/ER"),
        T_DATA("82801E Ethernet Controller 0", "82801E 0"),
        T_DATA("82801E Ethernet Controller 1", "82801E 1"),
        T_DATA("83c170 EPIC/100 Fast Ethernet Adapter", "83c170 EPIC/100"),
        T_DATA("83c175 EPIC/100 Fast Ethernet Adapter", "83c175 EPIC/100"),
        T_DATA("83C885 NT50 DigitalScape Fast Ethernet", "83C885 NT50 DigitalScape"),
        T_DATA("88E8001 Gigabit Ethernet Controller", "88E8001"),
        T_DATA("88E8021 PCI-X IPMI Gigabit Ethernet Controller", "88E8021 IPMI"),
        T_DATA("88E8022 PCI-X IPMI Gigabit Ethernet Controller", "88E8022 IPMI"),
        T_DATA("88E8035 PCI-E Fast Ethernet Controller", "88E8035"),
        T_DATA("88E8036 PCI-E Fast Ethernet Controller", "88E8036"),
        T_DATA("88E8038 PCI-E Fast Ethernet Controller", "88E8038"),
        T_DATA("88E8039 PCI-E Fast Ethernet Controller", "88E8039"),
        T_DATA("88E8040 PCI-E Fast Ethernet Controller", "88E8040"),
        T_DATA("88E8040T PCI-E Fast Ethernet Controller", "88E8040T"),
        T_DATA("88E8042 PCI-E Fast Ethernet Controller", "88E8042"),
        T_DATA("88E8048 PCI-E Fast Ethernet Controller", "88E8048"),
        T_DATA("88E8050 PCI-E ASF Gigabit Ethernet Controller", "88E8050 ASF"),
        T_DATA("88E8052 PCI-E ASF Gigabit Ethernet Controller", "88E8052 ASF"),
        T_DATA("88E8053 PCI-E Gigabit Ethernet Controller", "88E8053"),
        T_DATA("88E8055 PCI-E Gigabit Ethernet Controller", "88E8055"),
        T_DATA("88E8056 PCI-E Gigabit Ethernet Controller", "88E8056"),
        T_DATA("88E8057 PCI-E Gigabit Ethernet Controller", "88E8057"),
        T_DATA("88E8058 PCI-E Gigabit Ethernet Controller", "88E8058"),
        T_DATA("88E8061 PCI-E IPMI Gigabit Ethernet Controller", "88E8061 IPMI"),
        T_DATA("88E8062 PCI-E IPMI Gigabit Ethernet Controller", "88E8062 IPMI"),
        T_DATA("88E8070 based Ethernet Controller", "88E8070 based"),
        T_DATA("88E8071 PCI-E Gigabit Ethernet Controller", "88E8071"),
        T_DATA("88E8072 PCI-E Gigabit Ethernet Controller", "88E8072"),
        T_DATA("88E8075 PCI-E Gigabit Ethernet Controller", "88E8075"),
        T_DATA("88EC032 Ethernet Controller", "88EC032"),
        T_DATA("88EC033 PCI-E Fast Ethernet Controller", "88EC033"),
        T_DATA("88EC034 Ethernet Controller", "88EC034"),
        T_DATA("88EC036 PCI-E Gigabit Ethernet Controller", "88EC036"),
        T_DATA("88EC042 Ethernet Controller", "88EC042"),
        T_DATA("88W8363 [TopDog] 802.11n Wireless", "88W8363"),
        T_DATA("88W8366 [TopDog] 802.11n Wireless", "88W8366"),
        T_DATA("88W8388 802.11a/b/g WLAN", "88W8388"),
        T_DATA("88W8687 [TopDog] 802.11b/g Wireless", "88W8687"),
        T_DATA("88W8764 [Avastar] 802.11n Wireless", "88W8764"),
        T_DATA("88W8897 [AVASTAR] 802.11ac Wireless", "88W8897"),
        T_DATA("A90-211WG-01 802.11g Adapter [Intersil ISL3887]", "A90-211WG-01"),
        T_DATA("A9T wireless 802.11bg", "A9T"),
        T_DATA("AboCom Systems Inc [WN2001 Prolink Wireless-N Nano Adapter]", "AboCom Systems Inc"),
        T_DATA("AC1000 Gigabit Ethernet", "AC1000"),
        T_DATA("AC1001 Gigabit Ethernet", "AC1001"),
        T_DATA("AC1003 Gigabit Ethernet", "AC1003"),
        T_DATA("AC9100 Gigabit Ethernet", "AC9100"),
        T_DATA("AceNIC Gigabit Ethernet", "AceNIC"),
        T_DATA("AceNIC Gigabit Ethernet (Copper)", "AceNIC"),
        T_DATA("Acer Gobi 2000 Wireless Modem", "Acer Gobi 2000"),
        T_DATA("Acer Gobi Wireless Modem", "Acer Gobi"),
        T_DATA("ADM8511 Pegasus II Ethernet", "ADM8511 Pegasus II"),
        T_DATA("ADMtek ADM8515 NIC", "ADMtek ADM8515"),
        T_DATA("ADMtek Centaur-C rev 17 [D-Link DFE-680TX] CardBus Fast Ethernet Adapter",
               "ADMtek Centaur-C"),
        T_DATA("ADSL Modem", NULL),
        T_DATA("AE1000 v1 802.11n [Ralink RT3572]", "AE1000"),
        T_DATA("AE1200 802.11bgn Wireless Adapter [Broadcom BCM43235]", "AE1200"),
        T_DATA("AE3000 802.11abgn (3x3) Wireless Adapter [Ralink RT3573]", "AE3000"),
        T_DATA("AG-225H 802.11bg", "AG-225H"),
        T_DATA("Air2210 54 Mbps Wireless Adapter", "Air2210"),
        T_DATA("Air2310 150 Mbps Wireless Adapter", "Air2310"),
        T_DATA("Airlink101 AWLL6070 802.11bgn Wireless Adapter [Ralink RT2770]",
               "Airlink101 AWLL6070"),
        T_DATA("Airlink101 AWLL6080 802.11bgn Wireless Adapter [Ralink RT2870]",
               "Airlink101 AWLL6080"),
        T_DATA("AirLive WL-1600USB 802.11g Adapter [Realtek RTL8187L]", "AirLive WL-1600USB"),
        T_DATA("AirLive WN-200USB wireless 11b/g/n dongle", "AirLive WN-200USB"),
        T_DATA("AirLive WN-360USB adapter", "AirLive WN-360USB"),
        T_DATA("AirLive X.USB 802.11abgn [Atheros AR9170+AR9104]", "AirLive X.USB"),
        T_DATA("AirPcap NX [Atheros AR9001U-(2)NG]", "AirPcap NX"),
        T_DATA("AirPlus G DWL-G120 Wireless Adapter(rev.C) [Intersil ISL3887]",
               "AirPlus G DWL-G120"),
        T_DATA("AirPlus G DWL-G122 Wireless Adapter(rev.A1) [Intersil ISL3880]",
               "AirPlus G DWL-G122"),
        T_DATA("AirPlus G DWL-G122 Wireless Adapter(rev.A2) [Intersil ISL3887]",
               "AirPlus G DWL-G122"),
        T_DATA("AirPlus G DWL-G122 Wireless Adapter(rev.B1) [Ralink RT2571]", "AirPlus G DWL-G122"),
        T_DATA("AirPlus G DWL-G122 Wireless Adapter(rev.C1) [Ralink RT2571W]",
               "AirPlus G DWL-G122"),
        T_DATA("AirPlus G DWL-G122 Wireless Adapter(rev.E1) [Ralink RT2070]", "AirPlus G DWL-G122"),
        T_DATA("Alcatel One Touch L100V / Telekom Speedstick LTE II",
               "Alcatel One Touch L100V / Telekom Speedstick II"),
        T_DATA("Allnet ALL0283 [AR5523]", "Allnet ALL0283"),
        T_DATA("Allnet ALL0283 [AR5523](no firmware)", "Allnet ALL0283"),
        T_DATA("Allnet ALL0298 v2 802.11bg", "Allnet ALL0298"),
        T_DATA("AM10 v1 802.11n [Ralink RT3072]", "AM10"),
        T_DATA("AMD-8111 Ethernet", "AMD-8111"),
        T_DATA("AN2720 USB-USB Bridge", "AN2720 USB-USB Bridge"),
        T_DATA("AN8513 Ethernet", "AN8513"),
        T_DATA("AN8515 Ethernet", "AN8515"),
        T_DATA("AN986A Ethernet", "AN986A"),
        T_DATA("AN986 Pegasus Ethernet", "AN986 Pegasus"),
        T_DATA("ANA620xx/ANA69011A", "ANA620xx/ANA69011A"),
        T_DATA("AN-WF500 802.11abgn + BT Wireless Adapter [Broadcom BCM43242]", "AN-WF500"),
        T_DATA("Aolynk WUB320g", "Aolynk WUB320g"),
        T_DATA("AR2413/AR2414 Wireless Network Adapter [AR5005G(S) 802.11bg]", "AR2413/AR2414"),
        T_DATA("AR2417 Wireless Network Adapter [AR5007G 802.11bg]", "AR2417"),
        T_DATA("AR2425 Wireless Network Adapter [AR5007EG 802.11bg]", "AR2425"),
        T_DATA("AR2427 802.11bg Wireless Network Adapter (PCI-Express)", "AR2427"),
        T_DATA("AR242x / AR542x Wireless Network Adapter (PCI-Express)", "AR242x / AR542x"),
        T_DATA("AR5210 Wireless Network Adapter [AR5000 802.11a]", "AR5210"),
        T_DATA("AR5211 Wireless Network Adapter [AR5001A 802.11a]", "AR5211"),
        T_DATA("AR5211 Wireless Network Adapter [AR5001X 802.11ab]", "AR5211"),
        T_DATA("AR5212/5213/2414 Wireless Network Adapter", "AR5212/5213/2414"),
        T_DATA("AR5212 802.11abg NIC (3CRDAG675)", "AR5212"),
        T_DATA("AR5212 802.11abg NIC", "AR5212"),
        T_DATA("AR5413/AR5414 Wireless Network Adapter [AR5006X(S) 802.11abg]", "AR5413/AR5414"),
        T_DATA("AR5416 Wireless Network Adapter [AR5008 802.11(a)bgn]", "AR5416"),
        T_DATA("AR5418 Wireless Network Adapter [AR5008E 802.11(a)bgn] (PCI-Express)", "AR5418"),
        T_DATA("AR5523", "AR5523"),
        T_DATA("AR5523 driver (no firmware)", "AR5523"),
        T_DATA("AR5523 (no firmware)", "AR5523"),
        T_DATA("AR7010 (no firmware)", "AR7010"),
        T_DATA("AR8121/AR8113/AR8114 Gigabit or Fast Ethernet", "AR8121/AR8113/AR8114"),
        T_DATA("AR8131 Gigabit Ethernet", "AR8131"),
        T_DATA("AR8132 Fast Ethernet", "AR8132"),
        T_DATA("AR8151 v1.0 Gigabit Ethernet", "AR8151 v1.0"),
        T_DATA("AR8151 v2.0 Gigabit Ethernet", "AR8151 v2.0"),
        T_DATA("AR8152 v1.1 Fast Ethernet", "AR8152"),
        T_DATA("AR8152 v2.0 Fast Ethernet", "AR8152 v2.0"),
        T_DATA("AR8161 Gigabit Ethernet", "AR8161"),
        T_DATA("AR8162 Fast Ethernet", "AR8162"),
        T_DATA("AR9160 Wireless Network Adapter [AR9001 802.11(a)bgn]", "AR9160"),
        T_DATA("AR9170 802.11n", "AR9170"),
        T_DATA("AR9170+AR9104 802.11abgn Wireless Adapter", "AR9170+AR9104"),
        T_DATA("AR9227 Wireless Network Adapter", "AR9227"),
        T_DATA("AR922X Wireless Network Adapter", "AR922X"),
        T_DATA("AR922X Wireless Network Adapter (Compex WLM200NX / Wistron DNMA-92)", "AR922X"),
        T_DATA("AR9271 802.11n", "AR9271"),
        T_DATA("AR9285 Wireless Network Adapter (PCI-Express)", "AR9285"),
        T_DATA("AR9285 Wireless Network Adapter (PCI-Express) (AW-NB037H 802.11bgn Wireless "
               "Half-size Mini PCIe Card [AR9002WB-1NGCD])",
               "AR9285"),
        T_DATA("AR9287 Wireless Network Adapter (PCI-Express)", "AR9287"),
        T_DATA("AR928X Wireless Network Adapter (PCI-Express)", "AR928X"),
        T_DATA("AR928X Wireless Network Adapter (PCI-Express) (EM306 802.11bgn Wireless Half-size "
               "Mini PCIe Card [AR9283])",
               "AR928X"),
        T_DATA("AR928X Wireless Network Adapter (PCI-Express) (T77H047.31 802.11bgn Wireless "
               "Half-size Mini PCIe Card [AR9283])",
               "AR928X"),
        T_DATA("AR93xx Wireless Network Adapter", "AR93xx"),
        T_DATA("AR93xx Wireless Network Adapter (Killer Wireless-N 1102 Half-size Mini PCIe Card "
               "[AR9382])",
               "AR93xx"),
        T_DATA("AR93xx Wireless Network Adapter (Killer Wireless-N 1103 Half-size Mini PCIe Card "
               "[AR9380])",
               "AR93xx"),
        T_DATA("AR9462 Wireless Network Adapter", "AR9462"),
        T_DATA("AR9462 Wireless Network Adapter (Wireless 1601 802.11abgn Adapter)", "AR9462"),
        T_DATA("AR9462 Wireless Network Adapter (Wireless 1802 802.11abgn Adapter)", "AR9462"),
        T_DATA("AR9485 Wireless Network Adapter", "AR9485"),
        T_DATA("AR9485 Wireless Network Adapter (AR9485WB-EG 802.11b/g/n mini-PCIe card on a "
               "series 3 laptop)",
               "AR9485"),
        T_DATA("AR9485 Wireless Network Adapter (AW-NE186H)", "AR9485"),
        T_DATA("AR958x 802.11abgn Wireless Network Adapter", "AR958x"),
        T_DATA("Arcadyan 802.11N Wireless Adapter", "Arcadyan"),
        T_DATA("Arcadyan WN4501 802.11b/g", "Arcadyan WN4501"),
        T_DATA("Arcadyan WN7512 802.11n", "Arcadyan WN7512"),
        T_DATA("Asus Gobi 2000 Wireless Modem", "Asus Gobi 2000"),
        T_DATA("Aterm PA-WL54GU", "Aterm PA-WL54GU"),
        T_DATA("Aterm WL300NU-AG", "Aterm WL300NU-AG"),
        T_DATA("Aterm WL300NU-G", "Aterm WL300NU-G"),
        T_DATA("Attansic L1 Gigabit Ethernet", "Attansic L1"),
        T_DATA("Attansic L2c Gigabit Ethernet", "Attansic L2c"),
        T_DATA("Attansic L2 Fast Ethernet", "Attansic L2"),
        T_DATA("AT-USB100", "AT-USB100"),
        T_DATA("AX88141 Fast Ethernet Controller", "AX88141"),
        T_DATA("AX88178", "AX88178"),
        T_DATA("AX88179 Gigabit Ethernet", "AX88179"),
        T_DATA("AX88179 Gigabit Ethernet [Sitecom]", "AX88179"),
        T_DATA("AX88179 Gigabit Ethernet [ThinkPad OneLink GigaLAN]", "AX88179"),
        T_DATA("AX88772A Fast Ethernet", "AX88772A"),
        T_DATA("AX88772", "AX88772"),
        T_DATA("AX88772B", "AX88772B"),
        T_DATA("AX88772B Fast Ethernet Controller", "AX88772B"),
        T_DATA("B404-BT Unified Wire Ethernet Controller", "B404-BT"),
        T_DATA("B404-BT Unified Wire Ethernet Controller [VF]", "B404-BT"),
        T_DATA("B420-SR Unified Wire Ethernet Controller", "B420-SR"),
        T_DATA("B420-SR Unified Wire Ethernet Controller [VF]", "B420-SR"),
        T_DATA("B504-BT Unified Wire Ethernet Controller", "B504-BT"),
        T_DATA("B504-BT Unified Wire Ethernet Controller [VF]", "B504-BT"),
        T_DATA("B520-SR Unified Wire Ethernet Controller", "B520-SR"),
        T_DATA("B520-SR Unified Wire Ethernet Controller [VF]", "B520-SR"),
        T_DATA("BCM43142 802.11b/g/n", "BCM43142"),
        T_DATA("BCM43143 802.11bgn (1x1) Wireless Adapter", "BCM43143"),
        T_DATA("BCM43143 WLAN card", "BCM43143"),
        T_DATA("BCM43236 802.11abgn Wireless Adapter", "BCM43236"),
        T_DATA("BCM43241 WLAN card", "BCM43241"),
        T_DATA("BCM43242 802.11abgn Wireless Adapter", "BCM43242"),
        T_DATA("BCM4329 WLAN card", "BCM4329"),
        T_DATA("BCM4330 WLAN card", "BCM4330"),
        T_DATA("BCM43340 WLAN card", "BCM43340"),
        T_DATA("BCM43341 WLAN card", "BCM43341"),
        T_DATA("BCM4334 WLAN card", "BCM4334"),
        T_DATA("BCM4335/BCM4339 WLAN card", "BCM4335/BCM4339"),
        T_DATA("BCM43362 WLAN card", "BCM43362"),
        T_DATA("BCM4350 802.11ac Wireless Network Adapter", "BCM4350"),
        T_DATA("BCM4354 WLAN card", "BCM4354"),
        T_DATA("BCM43567 802.11ac Wireless Network Adapter", "BCM43567"),
        T_DATA("BCM4356 802.11ac Wireless Network Adapter", "BCM4356"),
        T_DATA("BCM43570 802.11ac Wireless Network Adapter", "BCM43570"),
        T_DATA("BCM4358 802.11ac Wireless LAN SoC", "BCM4358"),
        T_DATA("BCM43602 802.11ac Wireless LAN SoC", "BCM43602"),
        T_DATA("BCM4401 100Base-T", "BCM4401"),
        T_DATA("BCM4401-B0 100Base-TX", "BCM4401-B0"),
        T_DATA("BCM4402 Integrated 10/100BaseT", "BCM4402"),
        T_DATA("BCM57301 NetXtreme-C 10Gb Ethernet Controller", "BCM57301 NetXtreme-C"),
        T_DATA("BCM57302 NetXtreme-C 10Gb/25Gb Ethernet Controller", "BCM57302 NetXtreme-C"),
        T_DATA("BCM57304 NetXtreme-C 10Gb/25Gb/40Gb/50Gb Ethernet Controller",
               "BCM57304 NetXtreme-C"),
        T_DATA("BCM57311 NetXtreme-C 10Gb RDMA Ethernet Controller", "BCM57311 NetXtreme-C"),
        T_DATA("BCM57312 NetXtreme-C 10Gb/25Gb RDMA Ethernet Controller", "BCM57312 NetXtreme-C"),
        T_DATA("BCM57314 NetXtreme-C 10Gb/25Gb/40Gb/50Gb RDMA Ethernet Controller",
               "BCM57314 NetXtreme-C"),
        T_DATA("BCM57402 NetXtreme-E 10Gb Ethernet Controller", "BCM57402 NetXtreme-E"),
        T_DATA("BCM57402 NetXtreme-E Ethernet Partition", "BCM57402 NetXtreme-E Partition"),
        T_DATA("BCM57404 NetXtreme-E 10Gb/25Gb Ethernet Controller", "BCM57404 NetXtreme-E"),
        T_DATA("BCM57404 NetXtreme-E Ethernet Partition", "BCM57404 NetXtreme-E Partition"),
        T_DATA("BCM57406 NetXtreme-E 10GBASE-T Ethernet Controller", "BCM57406 NetXtreme-E"),
        T_DATA("BCM57406 NetXtreme-E Ethernet Partition", "BCM57406 NetXtreme-E Partition"),
        T_DATA("BCM57407 NetXtreme-E 10GBase-T Ethernet Controller", "BCM57407 NetXtreme-E"),
        T_DATA("BCM57407 NetXtreme-E 25Gb Ethernet Controller", "BCM57407 NetXtreme-E"),
        T_DATA("BCM57412 NetXtreme-E 10Gb RDMA Ethernet Controller", "BCM57412 NetXtreme-E"),
        T_DATA("BCM57412 NetXtreme-E Ethernet Partition", "BCM57412 NetXtreme-E Partition"),
        T_DATA("BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller", "BCM57414 NetXtreme-E"),
        T_DATA("BCM57414 NetXtreme-E Ethernet Partition", "BCM57414 NetXtreme-E Partition"),
        T_DATA("BCM57414 NetXtreme-E RDMA Partition", "BCM57414 NetXtreme-E Partition"),
        T_DATA("BCM57416 NetXtreme-E 10GBase-T RDMA Ethernet Controller", "BCM57416 NetXtreme-E"),
        T_DATA("BCM57416 NetXtreme-E 10Gb RDMA Ethernet Controller", "BCM57416 NetXtreme-E"),
        T_DATA("BCM57416 NetXtreme-E Ethernet Partition", "BCM57416 NetXtreme-E Partition"),
        T_DATA("BCM57416 NetXtreme-E RDMA Partition", "BCM57416 NetXtreme-E Partition"),
        T_DATA("BCM57417 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller", "BCM57417 NetXtreme-E"),
        T_DATA("BCM57417 NetXtreme-E 10GBASE-T RDMA Ethernet Controller", "BCM57417 NetXtreme-E"),
        T_DATA("BCM57417 NetXtreme-E Ethernet Partition", "BCM57417 NetXtreme-E Partition"),
        T_DATA("BCM57840 NetXtreme II 10/20-Gigabit Ethernet", "BCM57840 NetXtreme II"),
        T_DATA("BCM57840 NetXtreme II 10 Gigabit Ethernet", "BCM57840 NetXtreme II"),
        T_DATA("BCM57840 NetXtreme II Ethernet Multi Function", "BCM57840 NetXtreme II"),
        T_DATA("Belkin F5D5005 Gigabit Desktop Network PCI Card", "Belkin F5D5005"),
        T_DATA("ben-wpan, AT86RF230-based", "ben-wpan AT86RF230-based"),
        T_DATA("BladeCenter-H 10-Gigabit Ethernet High Speed Daughter Card",
               "BladeCenter-H High Speed Daughter"),
        T_DATA("BladeEngine2 10Gb Gen2 PCIe Network Adapter", "BladeEngine2 Gen2"),
        T_DATA("BladeEngine3 10Gb Gen2 PCIe Network Adapter", "BladeEngine3 Gen2"),
        T_DATA("BLOB boot loader firmware", "BLOB boot loader firmware"),
        T_DATA("Broadcom NetXtreme BCM5701 Gigabit Ethernet", "Broadcom NetXtreme BCM5701"),
        T_DATA("BWIFI-USB54AR 802.11bg", "BWIFI-USB54AR"),
        T_DATA("Cardbus Ethernet 10/100", NULL),
        T_DATA("Cassini 10/100/1000", "Cassini"),
        T_DATA("CE Media Processor Gigabit Ethernet Controller", NULL),
        T_DATA("Centrino Advanced-N 6200", "Centrino Advanced-N 6200"),
        T_DATA("Centrino Advanced-N 6205 [Taylor Peak]", "Centrino Advanced-N 6205"),
        T_DATA("Centrino Advanced-N 6230 [Rainbow Peak]", "Centrino Advanced-N 6230"),
        T_DATA("Centrino Advanced-N 6235", "Centrino Advanced-N 6235"),
        T_DATA("Centrino Advanced-N + WiMAX 6250 [Kilmer Peak]", "Centrino Advanced-N 6250"),
        T_DATA("Centrino Ultimate-N 6300", "Centrino Ultimate-N 6300"),
        T_DATA("Centrino Wireless-N 1000 [Condor Peak]", "Centrino 1000"),
        T_DATA("Centrino Wireless-N 100", "Centrino 100"),
        T_DATA("Centrino Wireless-N 1030 [Rainbow Peak]", "Centrino 1030"),
        T_DATA("Centrino Wireless-N 105", "Centrino 105"),
        T_DATA("Centrino Wireless-N 130", "Centrino 130"),
        T_DATA("Centrino Wireless-N 135", "Centrino 135"),
        T_DATA("Centrino Wireless-N 2200", "Centrino 2200"),
        T_DATA("Centrino Wireless-N 2230", "Centrino 2230"),
        T_DATA("Centrino Wireless-N + WiMAX 6150", "Centrino 6150"),
        T_DATA("CG-WLUSB10 Corega Wireless USB Adapter", "CG-WLUSB10 Corega"),
        T_DATA("CG-WLUSB2GNL", "CG-WLUSB2GNL"),
        T_DATA("CG-WLUSB2GNR Corega Wireless USB Adapter", "CG-WLUSB2GNR Corega"),
        T_DATA("CG-WLUSB2GO", "CG-WLUSB2GO"),
        T_DATA("CG-WLUSB2GPX [Ralink RT2571W]", "CG-WLUSB2GPX"),
        T_DATA("CG-WLUSB2GT 802.11g Wireless Adapter [Intersil ISL3880]", "CG-WLUSB2GT"),
        T_DATA("CG-WLUSB2GTST 802.11g Wireless Adapter [Intersil ISL3887]", "CG-WLUSB2GTST"),
        T_DATA("CG-WLUSB300AGN", "CG-WLUSB300AGN"),
        T_DATA("CG-WLUSB300GNM", "CG-WLUSB300GNM"),
        T_DATA("CG-WLUSB300GNS", "CG-WLUSB300GNS"),
        T_DATA("CK804 Ethernet Controller", "CK804"),
        T_DATA("CK8S Ethernet Controller", "CK8S"),
        T_DATA("cLOM8214 1/10GbE Controller", "cLOM8214"),
        T_DATA("CMOTECH CDMA Technologies modem", "CMOTECH"),
        T_DATA("Cohiba 802.11g Wireless Mini adapter [Intersil ISL3887]", "Cohiba"),
        T_DATA("Conceptronic C300RU v1 802.11bgn Wireless Adapter [Ralink RT2870]",
               "Conceptronic C300RU"),
        T_DATA("Conceptronic C300RU v2 802.11bgn Wireless Adapter [Ralink RT2770]",
               "Conceptronic C300RU"),
        T_DATA("Conceptronic C54RU v2 802.11bg Wireless Adapter [Ralink RT2571]",
               "Conceptronic C54RU"),
        T_DATA("Conceptronic C54RU v3 802.11bg Wireless Adapter [Ralink RT2571W]",
               "Conceptronic C54RU"),
        T_DATA("Connect2Air E-5400 802.11g Wireless Adapter", "Connect2Air E-5400"),
        T_DATA("Connect2Air E-5400 D1700 802.11g Wireless Adapter [Intersil ISL3887]",
               "Connect2Air E-5400 D1700"),
        T_DATA("CPWUE001 USB/Ethernet Adapter", "CPWUE001"),
        T_DATA("CWD-854 rev F", "CWD-854"),
        T_DATA("CWD-854 [RT2573]", "CWD-854"),
        T_DATA("CWD-854 Wireless 802.11g 54Mbps Network Adapter [RTL8187]", "CWD-854"),
        T_DATA("DECchip 21040 [Tulip]", "DECchip 21040"),
        T_DATA("DECchip 21041 [Tulip Pass 3]", "DECchip 21041"),
        T_DATA("DECchip 21140 [FasterNet]", "DECchip 21140"),
        T_DATA("DECchip 21142/43", "DECchip 21142/43"),
        T_DATA("DFE-680TXD CardBus PC Card", "DFE-680TXD"),
        T_DATA("DFE-690TXD CardBus PC Card", "DFE-690TXD"),
        T_DATA("DGE-528T Gigabit Ethernet Adapter", "DGE-528T"),
        T_DATA("DGE-528T Gigabit Ethernet Adapter (DGE-560T PCI Express (x1) Gigabit Ethernet "
               "Adapter)",
               "DGE-528T"),
        T_DATA("DGE-530T Gigabit Ethernet Adapter (rev 11)", "DGE-530T"),
        T_DATA("DGE-530T Gigabit Ethernet Adapter (rev.C1) [Realtek RTL8169]", "DGE-530T"),
        T_DATA("DGE-550SX PCI-X Gigabit Ethernet Adapter", "DGE-550SX"),
        T_DATA("DGE-550T Gigabit Ethernet Adapter V.B1", "DGE-550T V.B1"),
        T_DATA("DGE-560SX PCI Express Gigabit Ethernet Adapter", "DGE-560SX"),
        T_DATA("DGE-560T PCI Express Gigabit Ethernet Adapter", "DGE-560T"),
        T_DATA("DH8900CC Series Gigabit Backplane Network Connection", "DH8900CC Backplane"),
        T_DATA("DH8900CC Series Gigabit Fiber Network Connection", "DH8900CC"),
        T_DATA("DH8900CC Series Gigabit Network Connection", "DH8900CC"),
        T_DATA("DH8900CC Series Gigabit SFP Network Connection", "DH8900CC SFP"),
        T_DATA("Direct Connect", "Direct Connect"),
        T_DATA("DL10050 Sundance Ethernet (DFE-550TX/FX)", "DL10050 Sundance"),
        T_DATA("DL10050 Sundance Ethernet (DFE-580TX)", "DL10050 Sundance"),
        T_DATA("DL10050 Sundance Ethernet", "DL10050 Sundance"),
        T_DATA("DL2000-based Gigabit Ethernet", "DL2000-based"),
        T_DATA("DM9000E Fast Ethernet Adapter", "DM9000E"),
        T_DATA("DM9601 Fast Ethernet Adapter", "DM9601"),
        T_DATA("DP83065 [Saturn] 10/100/1000 Ethernet Controller", "DP83065"),
        T_DATA("DP83815 (MacPhyter) Ethernet Controller (Aculab E1/T1 PMXc cPCI carrier card)",
               "DP83815"),
        T_DATA("DP83815 (MacPhyter) Ethernet Controller", "DP83815"),
        T_DATA("DP83820 10/100/1000 Ethernet Controller", "DP83820"),
        T_DATA("DrayTek Vigor N61 802.11bgn Wireless Adapter [Ralink RT2870]", "DrayTek Vigor N61"),
        T_DATA("DRP-32TXD Cardbus PC Card", "DRP-32TXD"),
        T_DATA("DSB-650 10Mbps Ethernet [klsi]", "DSB-650"),
        T_DATA("DSB-650C Ethernet [klsi]", "DSB-650C"),
        T_DATA("DSB-650 Ethernet [pegasus]", "DSB-650"),
        T_DATA("DSB-650TX Ethernet [pegasus]", "DSB-650TX"),
        T_DATA("DSB-650TX-PNA Ethernet [pegasus]", "DSB-650TX-PNA"),
        T_DATA("Dual Band Wireless-AC 3165 Plus Bluetooth", "Wireless-AC 3165"),
        T_DATA("DUB-E100 Fast Ethernet Adapter(rev.A) [ASIX AX88172]", "DUB-E100"),
        T_DATA("DUB-E100 Fast Ethernet Adapter(rev.B1) [ASIX AX88772]", "DUB-E100"),
        T_DATA("DUB-E100 Fast Ethernet Adapter(rev.C1) [ASIX AX88772]", "DUB-E100"),
        T_DATA("DU-E100 Ethernet [pegasus]", "DU-E100"),
        T_DATA("DU-E10 Ethernet [klsi]", "DU-E10"),
        T_DATA("DU-E10 Ethernet [pegasus]", "DU-E10"),
        T_DATA("DWA-110 Wireless G Adapter(rev.A1) [Ralink RT2571W]", "DWA-110"),
        T_DATA("DWA-110 Wireless G Adapter(rev.B) [Ralink RT2870]", "DWA-110"),
        T_DATA("DWA-111 802.11bg Wireless Adapter [Ralink RT2571W]", "DWA-111"),
        T_DATA("DWA-121 802.11n Wireless N 150 Pico Adapter [Realtek RTL8188CUS]",
               "DWA-121 150 Pico"),
        T_DATA("DWA-123 Wireless N 150 Adapter(rev.A1) [Ralink RT3370]", "DWA-123 150"),
        T_DATA("DWA-125 Wireless N 150 Adapter(rev.A1) [Ralink RT3070]", "DWA-125 150"),
        T_DATA("DWA-125 Wireless N 150 Adapter(rev.A2) [Ralink RT3070]", "DWA-125 150"),
        T_DATA("DWA-125 Wireless N 150 Adapter(rev.A3) [Ralink RT5370]", "DWA-125 150"),
        T_DATA("DWA-126 802.11n Wireless Adapter [Atheros AR9271]", "DWA-126"),
        T_DATA("DWA-127 Wireless N 150 High-Gain Adapter(rev.A1) [Ralink RT3070]",
               "DWA-127 150 High-Gain"),
        T_DATA("DWA-130 802.11n Wireless N Adapter(rev.B) [Ralink RT2870]", "DWA-130"),
        T_DATA("DWA-130 802.11n Wireless N Adapter(rev.D) [Atheros AR9170+AR9102]", "DWA-130"),
        T_DATA("DWA-133 802.11n Wireless N Adapter [Realtek RTL8192CU]", "DWA-133"),
        T_DATA("DWA-135 802.11n Wireless N Adapter(rev.A1) [Realtek RTL8192CU]", "DWA-135"),
        T_DATA("DWA-140 RangeBooster N Adapter(rev.B1) [Ralink RT2870]", "DWA-140 RangeBooster N"),
        T_DATA("DWA-140 RangeBooster N Adapter(rev.B2) [Ralink RT3072]", "DWA-140 RangeBooster N"),
        T_DATA("DWA-140 RangeBooster N Adapter(rev.B3) [Ralink RT2870]", "DWA-140 RangeBooster N"),
        T_DATA("DWA-140 RangeBooster N Adapter(rev.B3) [Ralink RT5372]", "DWA-140 RangeBooster N"),
        T_DATA("DWA-160 802.11abgn Xtreme N Dual Band Adapter(rev.A1) [Atheros AR9170+AR9104]",
               "DWA-160 Xtreme N"),
        T_DATA("DWA-160 802.11abgn Xtreme N Dual Band Adapter(rev.A2) [Atheros AR9170+AR9104]",
               "DWA-160 Xtreme N"),
        T_DATA("DWA-160 802.11abgn Xtreme N Dual Band Adapter(rev.B2) [Ralink RT5572]",
               "DWA-160 Xtreme N"),
        T_DATA("DWA-160 Xtreme N Dual Band USB Adapter(rev.B) [Ralink RT2870]", "DWA-160 Xtreme N"),
        T_DATA("DWL-510 / DWL-610 802.11b [Realtek RTL8180L]", "DWL-510 / DWL-610"),
        T_DATA("DWL-AG122 [Atheros AR5523]", "DWL-AG122"),
        T_DATA("DWL-AG122 (no firmware) [Atheros AR5523]", "DWL-AG122"),
        T_DATA("DWL-AG132 [Atheros AR5523]", "DWL-AG132"),
        T_DATA("DWL-AG132 (no firmware) [Atheros AR5523]", "DWL-AG132"),
        T_DATA("DWL-G120 Spinnaker 802.11g [Intersil ISL3886]", "DWL-G120 Spinnaker"),
        T_DATA("DWL-G132 [Atheros AR5523]", "DWL-G132"),
        T_DATA("DWL-G132 (no firmware) [Atheros AR5523]", "DWL-G132"),
        T_DATA("DY-WL10 802.11abgn Adapter [Broadcom BCM4323]", "DY-WL10"),
        T_DATA("E180v", "E180v"),
        T_DATA("E45 Ethernet [klsi]", "E45"),
        T_DATA("E815", "E815"),
        T_DATA("EA101 10 Mbps 10BASE-T Ethernet [Kawasaki LSI KL5KLUSB101B]", "EA101"),
        T_DATA("EasiDock Ethernet", "EasiDock"),
        T_DATA("EH103 Wireless G Adapter", "EH103"),
        T_DATA("Eminent EM4045 [Broadcom 4320 USB]", "Eminent EM4045"),
        T_DATA("EN-1216 Ethernet Adapter", "EN-1216"),
        T_DATA("EN-1217 Ethernet Adapter", "EN-1217"),
        T_DATA("Enet2 Ethernet [klsi]", "Enet2"),
        T_DATA("Enet Ethernet [klsi]", "Enet"),
        T_DATA("EnGenius 802.11n Wireless USB Adapter", "EnGenius"),
        T_DATA("ENUWI-N3 [802.11n Wireless N150 Adapter]", "ENUWI-N3"),
        T_DATA("EP-1427X-2 Ethernet Adapter [Acer]", "EP-1427X-2"),
        T_DATA("EP-9001-g 802.11g 54M WLAN Adapter", "EP-9001-g"),
        T_DATA("ET-131x PCI-E Ethernet Controller", "ET-131x"),
        T_DATA("ET32P2", "ET32P2"),
        T_DATA("ETG-US2", "ETG-US2"),
        T_DATA("Ethernet 100/10 MBit", NULL),
        T_DATA("Ethernet 10G 2P X520 Adapter", "2P X520"),
        T_DATA("Ethernet Adapter [A1277]", "A1277"),
        T_DATA("Ethernet Adapter", NULL),
        T_DATA("Ethernet adapter [U2L 100P-Y1]", "U2L 100P-Y1"),
        T_DATA("Ethernet Adaptive Virtual Function", "Adaptive Virtual Function"),
        T_DATA("Ethernet Connection (2) I218-LM", NULL),
        T_DATA("Ethernet Connection (2) I218-V", NULL),
        T_DATA("Ethernet Connection (2) I219-LM", NULL),
        T_DATA("Ethernet Connection (2) I219-V", NULL),
        T_DATA("Ethernet Connection (3) I218-LM", NULL),
        T_DATA("Ethernet Connection (3) I218-V", NULL),
        T_DATA("Ethernet Connection (3) I219-LM", NULL),
        T_DATA("Ethernet Connection (4) I219-LM", NULL),
        T_DATA("Ethernet Connection (4) I219-V", NULL),
        T_DATA("Ethernet Connection (5) I219-LM", NULL),
        T_DATA("Ethernet Connection (5) I219-V", NULL),
        T_DATA("Ethernet Connection (6) I219-LM", NULL),
        T_DATA("Ethernet Connection (6) I219-V", NULL),
        T_DATA("Ethernet Connection (7) I219-LM", NULL),
        T_DATA("Ethernet Connection (7) I219-V", NULL),
        T_DATA("Ethernet Connection (8) I219-LM", NULL),
        T_DATA("Ethernet Connection (8) I219-V", NULL),
        T_DATA("Ethernet Connection (9) I219-LM", NULL),
        T_DATA("Ethernet Connection (9) I219-V", NULL),
        T_DATA("Ethernet Connection I217-LM", "I217-LM"),
        T_DATA("Ethernet Connection I217-V", "I217-V"),
        T_DATA("Ethernet Connection I218-LM", "I218-LM"),
        T_DATA("Ethernet Connection I218-V", "I218-V"),
        T_DATA("Ethernet Connection I219-LM", "I219-LM"),
        T_DATA("Ethernet Connection I219-V", "I219-V"),
        T_DATA("Ethernet Connection I354 1.0 GbE Backplane", "I354 Backplane"),
        T_DATA("Ethernet Connection I354 2.5 GbE Backplane", "I354 Backplane"),
        T_DATA("Ethernet Connection I354", "I354"),
        T_DATA("Ethernet Connection X552 1000BASE-T", "X552"),
        T_DATA("Ethernet Connection X552 10 GbE Backplane", "X552 Backplane"),
        T_DATA("Ethernet Connection X552 10 GbE SFP+", "X552 SFP+"),
        T_DATA("Ethernet Connection X552 Backplane", "X552 Backplane"),
        T_DATA("Ethernet Connection X552 Virtual Function", "X552 Virtual Function"),
        T_DATA("Ethernet Connection X552/X557-AT 10GBASE-T", "X552/X557-AT"),
        T_DATA("Ethernet Connection X553 10 GbE SFP+", "X553 SFP+"),
        T_DATA("Ethernet Connection X553 1GbE", "X553"),
        T_DATA("Ethernet Connection X553 Backplane", "X553 Backplane"),
        T_DATA("Ethernet Connection X553/X557-AT 10GBASE-T", "X553/X557-AT"),
        T_DATA("Ethernet Connection X722 for 10GBASE-T", "X722"),
        T_DATA("Ethernet Connection X722 for 10GbE backplane", "X722"),
        T_DATA("Ethernet Connection X722 for 10GbE QSFP+", "X722"),
        T_DATA("Ethernet Connection X722 for 10GbE SFP+", "X722"),
        T_DATA("Ethernet Connection X722 for 1GbE", "X722"),
        T_DATA("Ethernet Controller 10-Gigabit X540-AT2", "X540-AT2"),
        T_DATA("Ethernet Controller 10G X550T", "X550T"),
        T_DATA("Ethernet Controller X540", "X540"),
        T_DATA("Ethernet Controller X710 for 10GBASE-T", "X710"),
        T_DATA("Ethernet Controller X710 for 10GbE backplane", "X710"),
        T_DATA("Ethernet Controller X710 for 10GbE QSFP+", "X710"),
        T_DATA("Ethernet Controller X710 for 10GbE SFP+", "X710"),
        T_DATA("Ethernet Controller X710/X557-AT 10GBASE-T", "X710/X557-AT"),
        T_DATA("Ethernet Controller XL710 for 20GbE backplane", "XL710"),
        T_DATA("Ethernet Controller XL710 for 40GbE backplane", "XL710"),
        T_DATA("Ethernet Controller XL710 for 40GbE QSFP+", "XL710"),
        T_DATA("Ethernet Controller XXV710 for 25GbE backplane", "XXV710"),
        T_DATA("Ethernet Controller XXV710 for 25GbE SFP28", "XXV710"),
        T_DATA("Ethernet Converged Network Adapter X520-Q1", "X520-Q1"),
        T_DATA("Ethernet Express Module X520-P2", "X520-P2"),
        T_DATA("Ethernet HN210E", "HN210E"),
        T_DATA("Ethernet", NULL),
        T_DATA("Ethernet Server Adapter X520-4", "X520-4"),
        T_DATA("Ethernet Switch FM10000 Host Interface", "FM10000"),
        T_DATA("Ethernet Switch FM10000 Host Virtual Interface", "FM10000"),
        T_DATA("Ethernet X520 10GbE Dual Port KX4 Mezz", "X520 KX4 Mezz"),
        T_DATA("Ether USB-T Ethernet [klsi]", "Ether USB-T"),
        T_DATA("ET/TX Ethernet [pegasus]", "ET/TX"),
        T_DATA("ET/TX-S Ethernet [pegasus2]", "ET/TX-S"),
        T_DATA("EUB-3701 EXT 802.11g Wireless Adapter [Ralink RT2571W]", "EUB-3701 EXT"),
        T_DATA("EUB600v1 802.11abgn Wireless Adapter [Ralink RT3572]", "EUB600v1"),
        T_DATA("EUB9706 802.11n Wireless Adapter [Ralink RT3072]", "EUB9706"),
        T_DATA("EUB9801 802.11abgn Wireless Adapter [Ralink RT3572]", "EUB9801"),
        T_DATA("EW-7711UTn nLite Wireless Adapter [Ralink RT2870]", "EW-7711UTn nLite"),
        T_DATA("EW-7717UN 802.11n Wireless Adapter [Ralink RT2870]", "EW-7717UN"),
        T_DATA("EW-7718UN 802.11n Wireless Adapter [Ralink RT2870]", "EW-7718UN"),
        T_DATA("EW-7722UTn 802.11n Wireless Adapter [Ralink RT307x]", "EW-7722UTn"),
        T_DATA("EW-7811Un 802.11n Wireless Adapter [Realtek RTL8188CUS]", "EW-7811Un"),
        T_DATA("Expedite E362", "Expedite E362"),
        T_DATA("Express Ethernet", "Express"),
        T_DATA("EZ Connect USB Ethernet", "EZ Connect"),
        T_DATA("F5D5050 100Mbps Ethernet", "F5D5050"),
        T_DATA("F5D5055 Gigabit Network Adapter [AX88xxx]", "F5D5055"),
        T_DATA("F5D6001 Wireless PCI Card [Realtek RTL8180]", "F5D6001"),
        T_DATA("F5D6020 v3000 Wireless PCMCIA Card [Realtek RTL8180]", "F5D6020 v3000"),
        T_DATA("F5D7000 v7000 Wireless G Desktop Card [Realtek RTL8185]", "F5D7000 v7000"),
        T_DATA("F5D7010 v7000 Wireless G Notebook Card [Realtek RTL8185]", "F5D7010 v7000"),
        T_DATA("F5D7050 Wireless G Adapter v1000/v2000 [Intersil ISL3887]", "F5D7050 v1000/v2000"),
        T_DATA("F5D7050 Wireless G Adapter v3000 [Ralink RT2571W]", "F5D7050 v3000"),
        T_DATA("F5D7050 Wireless G Adapter v4000 [Zydas ZD1211B]", "F5D7050 v4000"),
        T_DATA("F5D7050 Wireless G Adapter v5000 [Realtek RTL8187B]", "F5D7050 v5000"),
        T_DATA("F5D7051 802.11g Adapter v1000 [Broadcom 4320 USB]", "F5D7051 v1000"),
        T_DATA("F5D8053 N Wireless Adapter v3000 [Ralink RT2870]", "F5D8053 v3000"),
        T_DATA("F5D8053 N Wireless USB Adapter v1000/v4000 [Ralink RT2870]", "F5D8053 v1000/v4000"),
        T_DATA("F5D8053 N Wireless USB Adapter v3000 [Ralink RT2870]", "F5D8053 v3000"),
        T_DATA("F5D8055 N+ Wireless Adapter v1000 [Ralink RT2870]", "F5D8055 v1000"),
        T_DATA("F5D8055 N+ Wireless Adapter v2000 [Ralink RT3072]", "F5D8055 v2000"),
        T_DATA("F5D9050 Wireless G+ MIMO Network Adapter v3000 [Ralink RT2573]",
               "F5D9050 MIMO v3000"),
        T_DATA("F5D9050 Wireless G+ MIMO Network Adapter v4000 [Ralink RT2573]",
               "F5D9050 MIMO v4000"),
        T_DATA("F5U258 Host to Host cable", "F5U258 Host to Host cable"),
        T_DATA("F6D4050 N150 Enhanced Wireless Network Adapter v1000 [Ralink RT3070]",
               "F6D4050 N150 v1000"),
        T_DATA("F6D4050 N150 Enhanced Wireless Network Adapter v2000 [Ralink RT3070]",
               "F6D4050 N150 v2000"),
        T_DATA("F7D1101 v2 Basic Wireless Adapter [Ralink RT3370]", "F7D1101"),
        T_DATA("F7D1102 N150/Surf Micro Wireless Adapter v1000 [Realtek RTL8188CUS]",
               "F7D1102 N150/Surf v1000"),
        T_DATA("F7D2102 802.11n N300 Micro Wireless Adapter v3000 [Realtek RTL8192CU]",
               "F7D2102 N300 v3000"),
        T_DATA("F9L1004 802.11n Surf N300 XR Wireless Adapter [Realtek RTL8192CU]",
               "F9L1004 Surf N300 XR"),
        T_DATA("F9L1103 N750 DB 802.11abgn 2x3:3 [Ralink RT3573]", "F9L1103 N750"),
        T_DATA("FA101 Fast Ethernet USB 1.1", "FA101"),
        T_DATA("FA120 Fast Ethernet USB 2.0 [Asix AX88172 / AX8817x]", "FA120"),
        T_DATA("Farallon PN9000SX Gigabit Ethernet", "Farallon PN9000SX"),
        T_DATA("Farallon PN9100-T Gigabit Ethernet", "Farallon PN9100-T"),
        T_DATA("Fast Ethernet", NULL),
        T_DATA("FastLinQ QL41000 Series 10/25/40/50GbE Controller", "FastLinQ QL41000"),
        T_DATA("FastLinQ QL41000 Series Gigabit Ethernet Controller (SR-IOV VF)",
               "FastLinQ QL41000"),
        T_DATA("FastLinQ QL45000 Series 100GbE Controller", "FastLinQ QL45000"),
        T_DATA("FastLinQ QL45000 Series 25GbE Controller", "FastLinQ QL45000"),
        T_DATA("FastLinQ QL45000 Series 40GbE Controller", "FastLinQ QL45000"),
        T_DATA("FastLinQ QL45000 Series Gigabit Ethernet Controller (SR-IOV VF)",
               "FastLinQ QL45000"),
        T_DATA("FEther USB2-TX", "FEther USB2-TX"),
        T_DATA("FEther USB-TXC", "FEther USB-TXC"),
        T_DATA("FEther USB-TX Ethernet [pegasus]", "FEther USB-TX"),
        T_DATA("FEther USB-TXS", "FEther USB-TXS"),
        T_DATA("FNW-3602-TX CardBus Fast Ethernet", "FNW-3602-TX"),
        T_DATA("FNW-3603-TX CardBus Fast Ethernet", "FNW-3603-TX"),
        T_DATA("FPC-0106TX misprogrammed [RTL81xx]", "FPC-0106TX"),
        T_DATA("Fritz!WLAN N 2.4 [Atheros AR9001U]", "Fritz!WLAN N 2.4"),
        T_DATA("Fritz!WLAN N [Atheros AR9001U]", "Fritz!WLAN N"),
        T_DATA("Fritz!WLAN N v2 [Atheros AR9271]", "Fritz!WLAN N"),
        T_DATA("FRITZ WLAN N v2 [RT5572/rt2870.bin]", "FRITZ N"),
        T_DATA("G-200 v2 802.11bg", "G-200"),
        T_DATA("G-210H 802.11g Wireless Adapter", "G-210H"),
        T_DATA("G-220 v2 802.11bg", "G-220"),
        T_DATA("G240 802.11bg", "G240"),
        T_DATA("GA620 Gigabit Ethernet", "GA620"),
        T_DATA("GA630 Gigabit Ethernet", "GA630"),
        T_DATA("GEM 10/100/1000 Ethernet [ge]", "GEM"),
        T_DATA("Gigabit Ethernet Adapter", NULL),
        T_DATA("Gigabit Network Adapter", NULL),
        T_DATA("GigaCard Network Adapter", "GigaCard"),
        T_DATA("Gigaset USB Adapter 300", "Gigaset 300"),
        T_DATA("GL620USB-A GeneLink USB-USB Bridge", "GL620USB-A GeneLink USB-USB Bridge"),
        T_DATA("GlobeTrotter Express 7.2 v2", "GlobeTrotter Express 7.2"),
        T_DATA("Globetrotter GI0505 [iCON 505]", "Globetrotter GI0505"),
        T_DATA("Globetrotter HSDPA Modem", "Globetrotter"),
        T_DATA("Globetrotter HSUPA Modem (aka icon 451)", "Globetrotter"),
        T_DATA("Globetrotter HSUPA Modem (aka iCON HSUPA E)", "Globetrotter"),
        T_DATA("Globetrotter HSUPA Modem (icon 411 aka \"Vodafone K3760\")", "Globetrotter"),
        T_DATA("Globetrotter MO40x 3G Modem (GTM 382)", "Globetrotter MO40x"),
        T_DATA("GN-54G", "GN-54G"),
        T_DATA("GN-BR402W", "GN-BR402W"),
        T_DATA("GNIC-II PCI Gigabit Ethernet [Hamachi]", "GNIC-II"),
        T_DATA("GN-WB01GS", "GN-WB01GS"),
        T_DATA("GN-WB30N 802.11n WLAN Card", "GN-WB30N"),
        T_DATA("GN-WB31N 802.11n USB WLAN Card", "GN-WB31N"),
        T_DATA("GN-WB32L 802.11n USB WLAN Card", "GN-WB32L"),
        T_DATA("GN-WBKG", "GN-WBKG"),
        T_DATA("GN-WI05GS", "GN-WI05GS"),
        T_DATA("Gobi 2000", "Gobi 2000"),
        T_DATA("Gobi 2000 Wireless Modem", "Gobi 2000"),
        T_DATA("Gobi 3000 HSPA+ Modem", "Gobi 3000 HSPA+"),
        T_DATA("Gobi 9x15 Multimode 3G/4G LTE Modem (IP passthrough mode)", "Gobi 9x15"),
        T_DATA("Gobi 9x15 Multimode 3G/4G LTE Modem (NAT mode)", "Gobi 9x15"),
        T_DATA("Gobi Wireless Modem", "Gobi"),
        T_DATA("Goldpfeil P-LAN", "Goldpfeil P-LAN"),
        T_DATA("GT-B3730 Composite LTE device (Commercial)", "GT-B3730"),
        T_DATA("GU-1000T", "GU-1000T"),
        T_DATA("GWUS300 802.11n", "GWUS300"),
        T_DATA("GW-US300MiniS", "GW-US300MiniS"),
        T_DATA("GW-US300MiniW 802.11bgn Wireless Adapter", "GW-US300MiniW"),
        T_DATA("GW-US54GXS 802.11bg", "GW-US54GXS"),
        T_DATA("GW-US54GZ", "GW-US54GZ"),
        T_DATA("GW-US54HP", "GW-US54HP"),
        T_DATA("GW-US54Mini2", "GW-US54Mini2"),
        T_DATA("GW-US54Mini 802.11bg", "GW-US54Mini"),
        T_DATA("GW-US54ZGL 802.11bg", "GW-US54ZGL"),
        T_DATA("GWUSB2E", "GWUSB2E"),
        T_DATA("GW-USEco300 802.11bgn Wireless Adapter [Realtek RTL8192CU]", "GW-USEco300"),
        T_DATA("GW-USMicro300", "GW-USMicro300"),
        T_DATA("GW-USMini2N 802.11n Wireless Adapter [Ralink RT2870]", "GW-USMini2N"),
        T_DATA("GW-USNano2 802.11n Wireless Adapter [Realtek RTL8188CUS]", "GW-USNano2"),
        T_DATA("GW-USValue-EZ 802.11n Wireless Adapter [Realtek RTL8188CUS]", "GW-USValue-EZ"),
        T_DATA("Happy Meal 10/100 Ethernet [hme]", "Happy Meal"),
        T_DATA("Harmony 900/1100 Remote", "Harmony 900/1100 Remote"),
        T_DATA("HAWNU1 Hi-Gain Wireless-150N Network Adapter with Range Amplifier [Ralink RT3070]",
               "HAWNU1"),
        T_DATA("HCF 56k Modem", "HCF"),
        T_DATA("Hercules HWNUp-150 802.11n Wireless N Pico [Realtek RTL8188CUS]",
               "Hercules HWNUp-150 Pico"),
        T_DATA("HNE-300 (RealTek RTL8139c) [iPaq Networking]", "HNE-300"),
        T_DATA("HomeConnect 3C460", "HomeConnect 3C460"),
        T_DATA("@Home Networks Ethernet [klsi]", "@Home Networks"),
        T_DATA("HU200TS Wireless Adapter", "HU200TS"),
        T_DATA("HWDN1 Hi-Gain Wireless-300N Dish Adapter [Ralink RT2870]", "HWDN1"),
        T_DATA("HWDN2 Hi-Gain Wireless-150N Dish Adapter [Ralink RT2770]", "HWDN2"),
        T_DATA("HWGUSB2-54-LB", "HWGUSB2-54-LB"),
        T_DATA("HWGUSB2-54V2-AP", "HWGUSB2-54V2-AP"),
        T_DATA("HWGUSB2-54 WLAN", "HWGUSB2-54"),
        T_DATA("HWU54DM", "HWU54DM"),
        T_DATA("HWUN1 Hi-Gain Wireless-300N Adapter w/ Upgradable Antenna [Ralink RT2870]",
               "HWUN1"),
        T_DATA("HWUN2 Hi-Gain Wireless-150N Adapter w/ Upgradable Antenna [Ralink RT2770]",
               "HWUN2"),
        T_DATA("HWUN3 Hi-Gain Wireless-N Adapter [Ralink RT3070]", "HWUN3"),
        T_DATA("I210 Gigabit Backplane Connection", "I210 Backplane Connection"),
        T_DATA("I210 Gigabit Fiber Network Connection", "I210"),
        T_DATA("I210 Gigabit Network Connection", "I210"),
        T_DATA("I211 Gigabit Network Connection", "I211"),
        T_DATA("I350 Ethernet Controller Virtual Function", "I350 Virtual Function"),
        T_DATA("I350 Gigabit Backplane Connection", "I350 Backplane Connection"),
        T_DATA("I350 Gigabit Connection", "I350 Connection"),
        T_DATA("I350 Gigabit Fiber Network Connection", "I350"),
        T_DATA("I350 Gigabit Network Connection", "I350"),
        T_DATA("IC Plus IP100A Integrated 10/100 Ethernet MAC + PHY", "IC Plus IP100A"),
        T_DATA("IEEE 802.11g Wireless Network Adapter", NULL),
        T_DATA("IFU-WLM2 USB Wireless LAN Module (Wireless Mode)", "IFU-WLM2"),
        T_DATA("Integrated NetFlex-3/P", "NetFlex-3/P"),
        T_DATA("Intrepid2 GMAC (Sun GEM)", "Intrepid2 GMAC"),
        T_DATA("IOGear GWU513 v2 802.11bg Wireless Adapter [Intersil ISL3887]", "IOGear GWU513"),
        T_DATA("IP1000 Family Gigabit Ethernet", "IP1000"),
        T_DATA("iPad 2 (3G; 64GB)", "iPad 2"),
        T_DATA("iPad 3 (3G, 16 GB)", "iPad 3"),
        T_DATA("iPad 4/Mini1", "iPad 4/Mini1"),
        T_DATA("iPad", "iPad"),
        T_DATA("iPAQ Networking 10/100 Ethernet [pegasus2]", "iPAQ Networking"),
        T_DATA("iPhone 3G", "iPhone"),
        T_DATA("iPhone 3GS", "iPhone 3GS"),
        T_DATA("iPhone 4(CDMA)", "iPhone 4"),
        T_DATA("iPhone 4", "iPhone 4"),
        T_DATA("iPhone 4S", "iPhone 4S"),
        T_DATA("iPhone5/5C/5S/6", "iPhone5/5C/5S/6"),
        T_DATA("iPhone", "iPhone"),
        T_DATA("iRex Technologies Gobi 2000 Wireless Modem", "iRex Gobi 2000"),
        T_DATA("ISL3877 [Prism Indigo]", "ISL3877"),
        T_DATA("ISL3886IK", "ISL3886IK"),
        T_DATA("ISL3886 [Prism Javelin/Prism Xbow]", "ISL3886"),
        T_DATA("ISL3890 [Prism GT/Prism Duette]/ISL3886 [Prism Javelin/Prism Xbow]", "ISL3890"),
        T_DATA("ISP4022-based Ethernet NIC", "ISP4022-based"),
        T_DATA("ISP4032-based Ethernet IPv6 NIC", "ISP4032-based IPv6"),
        T_DATA("ISP8324 1/10GbE Converged Network Controller", "ISP8324"),
        T_DATA("ISP8324 1/10GbE Converged Network Controller (NIC VF)", "ISP8324"),
        T_DATA("ISY Wireless Micro Adapter IWL 2000 [RTL8188CUS]", "ISY IWL 2000"),
        T_DATA("JMC250 PCI Express Gigabit Ethernet Controller", "JMC250"),
        T_DATA("JMC260 PCI Express Fast Ethernet Controller", "JMC260"),
        T_DATA("K2 GMAC (Sun GEM)", "K2 GMAC"),
        T_DATA("K3565-Z HSDPA", "K3565-Z"),
        T_DATA("K3570-Z", "K3570-Z"),
        T_DATA("K3571-Z", "K3571-Z"),
        T_DATA("K4505-Z", "K4505-Z"),
        T_DATA("K5006-Z vodafone LTE/UMTS/GSM Modem/Networkcard", "K5006-Z vodafone"),
        T_DATA("KC2190 USB Host-to-Host cable", "KC2190 Host-to-Host cable"),
        T_DATA("Keebox W150NU 802.11bgn Wireless Adapter [Ralink RT3070]", "Keebox W150NU"),
        T_DATA("Killer E220x Gigabit Ethernet Controller", "Killer E220x"),
        T_DATA("Killer E2400 Gigabit Ethernet Controller", "Killer E2400"),
        T_DATA("KL5KUSB101B Ethernet [klsi]", "KL5KUSB101B"),
        T_DATA("KNU101TX 100baseTX Ethernet", "KNU101TX 100baseTX"),
        T_DATA("KSZ8842-PMQL 2-Port Ethernet Switch", "KSZ8842-PMQL"),
        T_DATA("KwikLink Host-Host Connector", "KwikLink Host-Host Connector"),
        T_DATA("LAN7500 Ethernet 10/100/1000 Adapter", "LAN7500"),
        T_DATA("LAN9420/LAN9420i", "LAN9420/LAN9420i"),
        T_DATA("LAN9512/LAN9514 Ethernet 10/100 Adapter (SAL10)", "LAN9512/LAN9514"),
        T_DATA("Laneed 100Mbps Ethernet LD-USB/TX [pegasus]", "Laneed LD-USB/TX"),
        T_DATA("LAN-GTJ/U2A", "LAN-GTJ/U2A"),
        T_DATA("LAN-W150N/U2 Wireless LAN Adapter", "LAN-W150N/U2"),
        T_DATA("LAN-W150/U2M Wireless LAN Adapter", "LAN-W150/U2M"),
        T_DATA("LAN-W300AN/U2 Wireless LAN Adapter", "LAN-W300AN/U2"),
        T_DATA("LAN-W300N/U2 Wireless LAN Adapter", "LAN-W300N/U2"),
        T_DATA("LAN-WN12/U2 Wireless LAN Adapter", "LAN-WN12/U2"),
        T_DATA("LAN-WN22/U2 Wireless LAN Adapter", "LAN-WN22/U2"),
        T_DATA("LapLink Gold USB-USB Bridge [net1080]", "LapLink Gold USB-USB Bridge"),
        T_DATA("LD-USB20", "LD-USB20"),
        T_DATA("LD-USBL/TX", "LD-USBL/TX"),
        T_DATA("LD-USB/TX", "LD-USB/TX"),
        T_DATA("LE920", "LE920"),
        T_DATA("Leaf Light HS", "Leaf Light HS"),
        T_DATA("Leaf SemiPro HS", "Leaf SemiPro HS"),
        T_DATA("LevelOne WUA-0605 N_Max Wireless USB Adapter", "LevelOne WUA-0605 N Max"),
        T_DATA("LevelOne WUA-0615 N_Max Wireless USB Adapter", "LevelOne WUA-0615 N Max"),
        T_DATA("Libertas", "Libertas"),
        T_DATA("Linksys WUSB54GP v1 OEM 802.11g Adapter [Intersil ISL3886]", "Linksys WUSB54GP"),
        T_DATA("Linksys WUSB54G v1 OEM 802.11g Adapter [Intersil ISL3886]", "Linksys WUSB54G"),
        T_DATA("Linux-USB \"CDC Subset\" Device, or Itsy (experimental)", "Linux-USB or Itsy"),
        T_DATA("Linux-USB Ethernet/RNDIS Gadget", "Linux-USB Gadget"),
        T_DATA("LN-028 Network USB 2.0 Adapter", "LN-028"),
        T_DATA("LN-031 10/100/1000 Ethernet Adapter", "LN-031"),
        T_DATA("LNE100TX [Linksys EtherFast 10/100]", "LNE100TX"),
        T_DATA("LNE100TX", "LNE100TX"),
        T_DATA("lt4112 Gobi 4G Module Network Device", "lt4112 Gobi"),
        T_DATA("LTE4G O2 ZTE MF821D LTE/UMTS/GSM Modem/Networkcard", "LTE4G O2 ZTE MF821D"),
        T_DATA("LTE Storage Driver [CMC2xx]", "Storage Driver"),
        T_DATA("LUA2-TX Ethernet", "LUA2-TX"),
        T_DATA("LUA-KTX Ethernet", "LUA-KTX"),
        T_DATA("LUA-TX Ethernet", "LUA-TX"),
        T_DATA("LUA-TX Ethernet [pegasus]", "LUA-TX"),
        T_DATA("LUA-U2-GT 10/100/1000 Ethernet Adapter", "LUA-U2-GT"),
        T_DATA("LUA-U2-KTX Ethernet", "LUA-U2-KTX"),
        T_DATA("LW153 802.11n Adapter [ralink rt3070]", "LW153"),
        T_DATA("LW313 802.11n Adapter [ralink rt2770 + rt2720]", "LW313"),
        T_DATA("M-202 802.11bg", "M-202"),
        T_DATA("M5261 Ethernet Controller", "M5261"),
        T_DATA("M5632 Host-to-Host Link", "M5632 Host-to-Host Link"),
        T_DATA("Marvell 88W8388 802.11a/b/g WLAN", "Marvell 88W8388"),
        T_DATA("MC8700 Modem", "MC8700"),
        T_DATA("MCP04 Ethernet Controller", "MCP04"),
        T_DATA("MCP2A Ethernet Controller", "MCP2A"),
        T_DATA("MCP51 Ethernet Controller", "MCP51"),
        T_DATA("MCP55 Ethernet", "MCP55"),
        T_DATA("MCP61 Ethernet", "MCP61"),
        T_DATA("MCP65 Ethernet", "MCP65"),
        T_DATA("MCP67 Ethernet", "MCP67"),
        T_DATA("MCP73 Ethernet", "MCP73"),
        T_DATA("MCP77 Ethernet", "MCP77"),
        T_DATA("MCP79 Ethernet", "MCP79"),
        T_DATA("MCP89 Ethernet", "MCP89"),
        T_DATA("MCS7730 10/100 Mbps Ethernet adapter", "MCS7730"),
        T_DATA("MCS7830 10/100 Mbps Ethernet adapter", "MCS7830"),
        T_DATA("MCS7832 10/100 Mbps Ethernet adapter", "MCS7832"),
        T_DATA("Metronic 495257 wifi 802.11ng", "Metronic 495257"),
        T_DATA("MF110/MF627/MF636", "MF110/MF627/MF636"),
        T_DATA("MF632/ONDA ET502HS/MT505UP", "MF632/ONDA ET502HS/MT505UP"),
        T_DATA("MF820 4G LTE", "MF820"),
        T_DATA("Micolink USB2Ethernet [pegasus]", "Micolink USB2Ethernet"),
        T_DATA("MicroLink dLAN", "MicroLink dLAN"),
        T_DATA("MN-120 (ADMtek Centaur-C based)", "MN-120"),
        T_DATA("MN-130 (ADMtek Centaur-P based)", "MN-130"),
        T_DATA("MN-710 802.11g Wireless Adapter [Intersil ISL3886]", "MN-710"),
        T_DATA("model 01 Ethernet interface", "model 01"),
        T_DATA("model 01+ Ethernet", "model 01+"),
        T_DATA("Motorola 802.11n 5G USB Wireless Adapter", "Motorola"),
        T_DATA("Motorola 802.11n Dualband USB Wireless Adapter", "Motorola Dualband"),
        T_DATA("MP-PRX1 Ethernet", "MP-PRX1"),
        T_DATA("MS-3870 802.11bgn Wireless Module [Ralink RT3070]", "MS-3870"),
        T_DATA("MS-3871 802.11bgn Wireless Module [Ralink RT8070]", "MS-3871"),
        T_DATA("MSI-6861 802.11g WiFi adapter", "MSI-6861"),
        T_DATA("MT25400 Family [ConnectX-2 Virtual Function]", "MT25400"),
        T_DATA("MT25408 [ConnectX EN 10GigE 10GBaseT, PCIe 2.0 2.5GT/s]", "MT25408"),
        T_DATA("MT25408 [ConnectX EN 10GigE 10GBaseT, PCIe Gen2 5GT/s]", "MT25408"),
        T_DATA("MT25408 [ConnectX VPI - IB SDR / 10GigE]", "MT25408"),
        T_DATA("MT25418 [ConnectX VPI PCIe 2.0 2.5GT/s - IB DDR / 10GigE]", "MT25418"),
        T_DATA("MT25448 [ConnectX EN 10GigE, PCIe 2.0 2.5GT/s]", "MT25448"),
        T_DATA("MT26418 [ConnectX VPI PCIe 2.0 5GT/s - IB DDR / 10GigE]", "MT26418"),
        T_DATA("MT26428 [ConnectX VPI PCIe 2.0 5GT/s - IB QDR / 10GigE]", "MT26428"),
        T_DATA("MT26438 [ConnectX VPI PCIe 2.0 5GT/s - IB QDR / 10GigE Virtualization+]",
               "MT26438"),
        T_DATA("MT26448 [ConnectX EN 10GigE, PCIe 2.0 5GT/s]", "MT26448"),
        T_DATA("MT26468 [ConnectX EN 10GigE, PCIe 2.0 5GT/s Virtualization+]", "MT26468"),
        T_DATA("MT26478 [ConnectX EN 40GigE, PCIe 2.0 5GT/s]", "MT26478"),
        T_DATA("MT27500 Family [ConnectX-3]", "MT27500"),
        T_DATA("MT27500/MT27520 Family [ConnectX-3/ConnectX-3 Pro Virtual Function]",
               "MT27500/MT27520"),
        T_DATA("MT27510 Family", "MT27510"),
        T_DATA("MT27511 Family", "MT27511"),
        T_DATA("MT27520 Family [ConnectX-3 Pro]", "MT27520"),
        T_DATA("MT27530 Family", "MT27530"),
        T_DATA("MT27531 Family", "MT27531"),
        T_DATA("MT27540 Family", "MT27540"),
        T_DATA("MT27541 Family", "MT27541"),
        T_DATA("MT27550 Family", "MT27550"),
        T_DATA("MT27551 Family", "MT27551"),
        T_DATA("MT27560 Family", "MT27560"),
        T_DATA("MT27561 Family", "MT27561"),
        T_DATA("MT27600 [Connect-IB]", "MT27600"),
        T_DATA("MT27600 Family [Connect-IB Virtual Function]", "MT27600"),
        T_DATA("MT27700 Family [ConnectX-4]", "MT27700"),
        T_DATA("MT27700 Family [ConnectX-4 Virtual Function]", "MT27700"),
        T_DATA("MT27710 Family [ConnectX-4 Lx]", "MT27710"),
        T_DATA("MT27710 Family [ConnectX-4 Lx Virtual Function]", "MT27710"),
        T_DATA("MT27800 Family [ConnectX-5]", "MT27800"),
        T_DATA("MT27800 Family [ConnectX-5 Virtual Function]", "MT27800"),
        T_DATA("MT28800 Family [ConnectX-5 Ex]", "MT28800"),
        T_DATA("MT28800 Family [ConnectX-5 Ex Virtual Function]", "MT28800"),
        T_DATA("MT28908 Family [ConnectX-6]", "MT28908"),
        T_DATA("MT28908 Family [ConnectX-6 Virtual Function]", "MT28908"),
        T_DATA("MT416842 BlueField integrated ConnectX-5 network controller",
               "MT416842 BlueField ConnectX-5"),
        T_DATA("MT416842 BlueField multicore SoC family VF", "MT416842 BlueField VF"),
        T_DATA("MT51136", "MT51136"),
        T_DATA("MT52100", "MT52100"),
        T_DATA("MT53236", "MT53236"),
        T_DATA("MT7601U Wireless Adapter", "MT7601U"),
        T_DATA("MTD-8xx 100/10M Ethernet PCI Adapter", "MTD-8xx"),
        T_DATA("Multithreaded 10-Gigabit Ethernet Network Controller", NULL),
        T_DATA("MX98713", "MX98713"),
        T_DATA("MX987x5", "MX987x5"),
        T_DATA("Myri-10G Dual-Protocol NIC", "Myri-10G"),
        T_DATA("N10 Nano 802.11n Network Adapter [Realtek RTL8192CU]", "N10 Nano"),
        T_DATA("N220 802.11bgn Wireless Adapter", "N220"),
        T_DATA("N320-G2-CR 10GbE Dual Port Adapter", "N320-G2-CR"),
        T_DATA("N5HBZ0000055 802.11abgn Wireless Adapter [Atheros AR7010+AR9280]", "N5HBZ0000055"),
        T_DATA("Name: Voyager 1055 Laptop 802.11g Adapter [Broadcom 4320]", "Voyager 1055"),
        T_DATA("NC100 Network Everywhere Fast Ethernet 10/100", "NC100"),
        T_DATA("NE-34", "NE-34"),
        T_DATA("NET1080 USB-USB Bridge", "NET1080 USB-USB Bridge"),
        T_DATA("Netelligent 10/100 TX Embedded UTP", "Netelligent TX"),
        T_DATA("Netelligent 10/100 TX PCI UTP", "Netelligent TX"),
        T_DATA("Netelligent 10/100 TX UTP", "Netelligent TX"),
        T_DATA("Netelligent 10 T/2 PCI UTP/Coax", "Netelligent 10 T/2"),
        T_DATA("Netelligent 10 T PCI UTP", "Netelligent 10 T"),
        T_DATA("Netelligent Dual 10/100 TX PCI UTP", "Netelligent Dual TX"),
        T_DATA("Netelligent Integrated 10/100 TX UTP", "Netelligent TX"),
        T_DATA("NetFlex-3/P ThunderLAN 1.0", "NetFlex-3/P ThunderLAN 1.0"),
        T_DATA("NetFlex-3/P ThunderLAN 2.3", "NetFlex-3/P ThunderLAN 2.3"),
        T_DATA("NetLink BCM57780 Gigabit Ethernet PCIe", "NetLink BCM57780"),
        T_DATA("NetLink BCM57781 Gigabit Ethernet PCIe", "NetLink BCM57781"),
        T_DATA("NetLink BCM57785 Gigabit Ethernet PCIe", "NetLink BCM57785"),
        T_DATA("NetLink BCM57788 Gigabit Ethernet PCIe", "NetLink BCM57788"),
        T_DATA("NetLink BCM57790 Gigabit Ethernet PCIe", "NetLink BCM57790"),
        T_DATA("NetLink BCM57791 Gigabit Ethernet PCIe", "NetLink BCM57791"),
        T_DATA("NetLink BCM57795 Gigabit Ethernet PCIe", "NetLink BCM57795"),
        T_DATA("NetLink BCM5781 Gigabit Ethernet PCI Express", "NetLink BCM5781"),
        T_DATA("NetLink BCM5784M Gigabit Ethernet PCIe", "NetLink BCM5784M"),
        T_DATA("NetLink BCM5785 Fast Ethernet", "NetLink BCM5785"),
        T_DATA("NetLink BCM5785 Gigabit Ethernet", "NetLink BCM5785"),
        T_DATA("NetLink BCM5786 Gigabit Ethernet PCI Express", "NetLink BCM5786"),
        T_DATA("NetLink BCM5787F Fast Ethernet PCI Express", "NetLink BCM5787F"),
        T_DATA("NetLink BCM5787 Gigabit Ethernet PCI Express", "NetLink BCM5787"),
        T_DATA("NetLink BCM5787M Gigabit Ethernet PCI Express", "NetLink BCM5787M"),
        T_DATA("NetLink BCM5789 Gigabit Ethernet PCI Express", "NetLink BCM5789"),
        T_DATA("NetLink BCM5906 Fast Ethernet PCI Express", "NetLink BCM5906"),
        T_DATA("NetLink BCM5906M Fast Ethernet PCI Express", "NetLink BCM5906M"),
        T_DATA("NetMate2 Ethernet", "NetMate2"),
        T_DATA("NetMate Ethernet", "NetMate"),
        T_DATA("NetXen Dual Port 10GbE Multifunction Adapter for c-Class",
               "NetXen Multifunction for c-Class"),
        T_DATA("NetXtreme 5714S Gigabit Ethernet", "NetXtreme 5714S"),
        T_DATA("NetXtreme BCM5700 Gigabit Ethernet", "NetXtreme BCM5700"),
        T_DATA("NetXtreme BCM5701 Gigabit Ethernet", "NetXtreme BCM5701"),
        T_DATA("NetXtreme BCM5702A3 Gigabit Ethernet", "NetXtreme BCM5702A3"),
        T_DATA("NetXtreme BCM5702FE Gigabit Ethernet", "NetXtreme BCM5702FE"),
        T_DATA("NetXtreme BCM5702 Gigabit Ethernet", "NetXtreme BCM5702"),
        T_DATA("NetXtreme BCM5702X Gigabit Ethernet", "NetXtreme BCM5702X"),
        T_DATA("NetXtreme BCM5703 Gigabit Ethernet", "NetXtreme BCM5703"),
        T_DATA("NetXtreme BCM5703X Gigabit Ethernet", "NetXtreme BCM5703X"),
        T_DATA("NetXtreme BCM5704 Gigabit Ethernet", "NetXtreme BCM5704"),
        T_DATA("NetXtreme BCM5704S_2 Gigabit Ethernet", "NetXtreme BCM5704S 2"),
        T_DATA("NetXtreme BCM5704S Gigabit Ethernet", "NetXtreme BCM5704S"),
        T_DATA("NetXtreme BCM5705_2 Gigabit Ethernet", "NetXtreme BCM5705 2"),
        T_DATA("NetXtreme BCM5705 Gigabit Ethernet", "NetXtreme BCM5705"),
        T_DATA("NetXtreme BCM5705M_2 Gigabit Ethernet", "NetXtreme BCM5705M 2"),
        T_DATA("NetXtreme BCM5705M Gigabit Ethernet", "NetXtreme BCM5705M"),
        T_DATA("NetXtreme BCM5714 Gigabit Ethernet", "NetXtreme BCM5714"),
        T_DATA("NetXtreme BCM5715 Gigabit Ethernet", "NetXtreme BCM5715"),
        T_DATA("NetXtreme BCM5715S Gigabit Ethernet", "NetXtreme BCM5715S"),
        T_DATA("NetXtreme BCM5717 Gigabit Ethernet PCIe", "NetXtreme BCM5717"),
        T_DATA("NetXtreme BCM5718 Gigabit Ethernet PCIe", "NetXtreme BCM5718"),
        T_DATA("NetXtreme BCM5719 Gigabit Ethernet PCIe", "NetXtreme BCM5719"),
        T_DATA("NetXtreme BCM5720 Gigabit Ethernet PCIe", "NetXtreme BCM5720"),
        T_DATA("NetXtreme BCM5721 Gigabit Ethernet PCI Express", "NetXtreme BCM5721"),
        T_DATA("NetXtreme BCM5722 Gigabit Ethernet PCI Express", "NetXtreme BCM5722"),
        T_DATA("NetXtreme BCM5723 Gigabit Ethernet PCIe", "NetXtreme BCM5723"),
        T_DATA("NetXtreme BCM5725 Gigabit Ethernet PCIe", "NetXtreme BCM5725"),
        T_DATA("NetXtreme BCM5727 Gigabit Ethernet PCIe", "NetXtreme BCM5727"),
        T_DATA("NetXtreme BCM5751F Fast Ethernet PCI Express", "NetXtreme BCM5751F"),
        T_DATA("NetXtreme BCM5751 Gigabit Ethernet PCI Express", "NetXtreme BCM5751"),
        T_DATA("NetXtreme BCM5751M Gigabit Ethernet PCI Express", "NetXtreme BCM5751M"),
        T_DATA("NetXtreme BCM5752 Gigabit Ethernet PCI Express", "NetXtreme BCM5752"),
        T_DATA("NetXtreme BCM5752M Gigabit Ethernet PCI Express", "NetXtreme BCM5752M"),
        T_DATA("NetXtreme BCM5753F Fast Ethernet PCI Express", "NetXtreme BCM5753F"),
        T_DATA("NetXtreme BCM5753 Gigabit Ethernet PCI Express", "NetXtreme BCM5753"),
        T_DATA("NetXtreme BCM5753M Gigabit Ethernet PCI Express", "NetXtreme BCM5753M"),
        T_DATA("NetXtreme BCM5754 Gigabit Ethernet PCI Express", "NetXtreme BCM5754"),
        T_DATA("NetXtreme BCM5754M Gigabit Ethernet PCI Express", "NetXtreme BCM5754M"),
        T_DATA("NetXtreme BCM5755 Gigabit Ethernet PCI Express", "NetXtreme BCM5755"),
        T_DATA("NetXtreme BCM5755M Gigabit Ethernet PCI Express", "NetXtreme BCM5755M"),
        T_DATA("NetXtreme BCM5756ME Gigabit Ethernet PCI Express", "NetXtreme BCM5756ME"),
        T_DATA("NetXtreme BCM5761 10/100/1000BASE-T Ethernet", "NetXtreme BCM5761"),
        T_DATA("NetXtreme BCM5761e Gigabit Ethernet PCIe", "NetXtreme BCM5761e"),
        T_DATA("NetXtreme BCM5761 Gigabit Ethernet PCIe", "NetXtreme BCM5761"),
        T_DATA("NetXtreme BCM5762 Gigabit Ethernet PCIe", "NetXtreme BCM5762"),
        T_DATA("NetXtreme BCM5764M Gigabit Ethernet PCIe", "NetXtreme BCM5764M"),
        T_DATA("NetXtreme BCM57760 Gigabit Ethernet PCIe", "NetXtreme BCM57760"),
        T_DATA("NetXtreme BCM57761 Gigabit Ethernet PCIe", "NetXtreme BCM57761"),
        T_DATA("NetXtreme BCM57762 Gigabit Ethernet PCIe", "NetXtreme BCM57762"),
        T_DATA("NetXtreme BCM57764 Gigabit Ethernet PCIe", "NetXtreme BCM57764"),
        T_DATA("NetXtreme BCM57765 Gigabit Ethernet PCIe", "NetXtreme BCM57765"),
        T_DATA("NetXtreme BCM57766 Gigabit Ethernet PCIe", "NetXtreme BCM57766"),
        T_DATA("NetXtreme BCM57767 Gigabit Ethernet PCIe", "NetXtreme BCM57767"),
        T_DATA("NetXtreme BCM57782 Gigabit Ethernet PCIe", "NetXtreme BCM57782"),
        T_DATA("NetXtreme BCM57786 Gigabit Ethernet PCIe", "NetXtreme BCM57786"),
        T_DATA("NetXtreme BCM57787 Gigabit Ethernet PCIe", "NetXtreme BCM57787"),
        T_DATA("NetXtreme BCM5780 Gigabit Ethernet", "NetXtreme BCM5780"),
        T_DATA("NetXtreme BCM5780S Gigabit Ethernet", "NetXtreme BCM5780S"),
        T_DATA("NetXtreme BCM5782 Gigabit Ethernet", "NetXtreme BCM5782"),
        T_DATA("NetXtreme BCM5788 Gigabit Ethernet", "NetXtreme BCM5788"),
        T_DATA("NetXtreme BCM5901 100Base-TX", "NetXtreme BCM5901"),
        T_DATA("NetXtreme-C Ethernet Virtual Function", "NetXtreme-C Virtual Function"),
        T_DATA("NetXtreme-C RDMA Virtual Function", "NetXtreme-C Virtual Function"),
        T_DATA("NetXtreme-E Ethernet Virtual Function", "NetXtreme-E Virtual Function"),
        T_DATA("NetXtreme-E RDMA Virtual Function", "NetXtreme-E Virtual Function"),
        T_DATA(
            "NetXtreme II BCM5706 Gigabit Ethernet (NC370i Multifunction Gigabit Server Adapter)",
            "NetXtreme II BCM5706"),
        T_DATA(
            "NetXtreme II BCM5706 Gigabit Ethernet (NC370T MultifuNCtion Gigabit Server Adapter)",
            "NetXtreme II BCM5706"),
        T_DATA("NetXtreme II BCM5706 Gigabit Ethernet", "NetXtreme II BCM5706"),
        T_DATA(
            "NetXtreme II BCM5706S Gigabit Ethernet (NC370F MultifuNCtion Gigabit Server Adapter)",
            "NetXtreme II BCM5706S"),
        T_DATA("NetXtreme II BCM5706S Gigabit Ethernet", "NetXtreme II BCM5706S"),
        T_DATA("NetXtreme II BCM5708 Gigabit Ethernet", "NetXtreme II BCM5708"),
        T_DATA("NetXtreme II BCM5708S Gigabit Ethernet", "NetXtreme II BCM5708S"),
        T_DATA("NetXtreme II BCM5709 Gigabit Ethernet", "NetXtreme II BCM5709"),
        T_DATA("NetXtreme II BCM5709S Gigabit Ethernet", "NetXtreme II BCM5709S"),
        T_DATA("NetXtreme II BCM5716 Gigabit Ethernet", "NetXtreme II BCM5716"),
        T_DATA("NetXtreme II BCM5716S Gigabit Ethernet", "NetXtreme II BCM5716S"),
        T_DATA("NetXtreme II BCM57710 10-Gigabit PCIe [Everest]", "NetXtreme II BCM57710"),
        T_DATA("NetXtreme II BCM57711 10-Gigabit PCIe", "NetXtreme II BCM57711"),
        T_DATA("NetXtreme II BCM57711E 10-Gigabit PCIe", "NetXtreme II BCM57711E"),
        T_DATA("NetXtreme II BCM57712 10 Gigabit Ethernet Multi Function", "NetXtreme II BCM57712"),
        T_DATA("NetXtreme II BCM57712 10 Gigabit Ethernet", "NetXtreme II BCM57712"),
        T_DATA("NetXtreme II BCM57712 10 Gigabit Ethernet Virtual Function",
               "NetXtreme II BCM57712 Virtual Function"),
        T_DATA("NetXtreme II BCM57800 1/10 Gigabit Ethernet Multi Function",
               "NetXtreme II BCM57800"),
        T_DATA("NetXtreme II BCM57800 1/10 Gigabit Ethernet", "NetXtreme II BCM57800"),
        T_DATA("NetXtreme II BCM57800 1/10 Gigabit Ethernet Virtual Function",
               "NetXtreme II BCM57800 Virtual Function"),
        T_DATA("NetXtreme II BCM57810 10 Gigabit Ethernet Multi Function", "NetXtreme II BCM57810"),
        T_DATA("NetXtreme II BCM57810 10 Gigabit Ethernet", "NetXtreme II BCM57810"),
        T_DATA("NetXtreme II BCM57810 10 Gigabit Ethernet Virtual Function",
               "NetXtreme II BCM57810 Virtual Function"),
        T_DATA("NetXtreme II BCM57811 10 Gigabit Ethernet Multi Function", "NetXtreme II BCM57811"),
        T_DATA("NetXtreme II BCM57811 10-Gigabit Ethernet", "NetXtreme II BCM57811"),
        T_DATA("NetXtreme II BCM57811 10-Gigabit Ethernet Virtual Function",
               "NetXtreme II BCM57811 Virtual Function"),
        T_DATA("NetXtreme II BCM57840 10/20 Gigabit Ethernet Multi Function",
               "NetXtreme II BCM57840 10/20"),
        T_DATA("NetXtreme II BCM57840 10/20 Gigabit Ethernet", "NetXtreme II BCM57840 10/20"),
        T_DATA("NetXtreme II BCM57840 10/20 Gigabit Ethernet Virtual Function",
               "NetXtreme II BCM57840 10/20 Virtual Function"),
        T_DATA("nForce2 Ethernet Controller", "nForce2"),
        T_DATA("nForce3 Ethernet", "nForce3"),
        T_DATA("nForce Ethernet Controller", "nForce"),
        T_DATA("Nintendo Wi-Fi", "Nintendo"),
        T_DATA("NM10/ICH7 Family LAN Controller", "NM10/ICH7"),
        T_DATA("NovaTech NV-902W", "NovaTech NV-902W"),
        T_DATA("NUB100 Ethernet [pegasus]", "NUB100"),
        T_DATA("NUB-350 802.11g Wireless Adapter [Intersil ISL3887]", "NUB-350"),
        T_DATA("NUB-8301 802.11bg", "NUB-8301"),
        T_DATA("NV5000SC", "NV5000SC"),
        T_DATA("NW-3100 802.11b/g 54Mbps Wireless Network Adapter [zd1211]", "NW-3100"),
        T_DATA("NWD2105 802.11bgn Wireless Adapter [Ralink RT3070]", "NWD2105"),
        T_DATA("NWD-210N 802.11b/g/n-draft wireless adapter", "NWD-210N"),
        T_DATA("NWD211AN 802.11abgn Wireless Adapter [Ralink RT2870]", "NWD211AN"),
        T_DATA("NWD2205 802.11n Wireless N Adapter [Realtek RTL8192CU]", "NWD2205"),
        T_DATA("NWD-270N Wireless N-lite USB Adapter", "NWD-270N N-lite"),
        T_DATA("NWD271N 802.11n Wireless Adapter [Atheros AR9001U-(2)NG]", "NWD271N"),
        T_DATA("NX3031 Multifunction 1/10-Gigabit Server Adapter", "NX3031 Multifunction"),
        T_DATA("NXB-10GCX4 10-Gigabit Ethernet PCIe Adapter with CX4 copper interface",
               "NXB-10GCX4"),
        T_DATA("NXB-10GXSR 10-Gigabit Ethernet PCIe Adapter with SR-XFP optical interface",
               "NXB-10GXSR"),
        T_DATA("NXB-4GCU Quad Gigabit Ethernet PCIe Adapter with 1000-BASE-T interface",
               "NXB-4GCU Quad"),
        T_DATA("OC-2183/2185", "OC-2183/2185"),
        T_DATA("OC-2325", "OC-2325"),
        T_DATA("OC-2326", "OC-2326"),
        T_DATA("OCT To Fast Ethernet Converter", "OCT To Converter"),
        T_DATA("Olicard 100", "Olicard 100"),
        T_DATA("OneConnect 10Gb NIC (be3)", "OneConnect"),
        T_DATA("OneConnect NIC (Lancer)", "OneConnect"),
        T_DATA("OneConnect NIC (Skyhawk)", "OneConnect"),
        T_DATA("OneConnect NIC (Skyhawk-VF)", "OneConnect"),
        T_DATA("OneConnect OCe10100/OCe10102 Series 10 GbE", "OneConnect OCe10100/OCe10102"),
        T_DATA("On Networks N300MA 802.11bgn [Realtek RTL8192CU]", "On Networks N300MA"),
        T_DATA("Ovation MC551", "Ovation MC551"),
        T_DATA("PCAN-PCI CAN-Bus controller", "PCAN-PCI"),
        T_DATA("PCAN Pro", "PCAN Pro"),
        T_DATA("PCAN-USB", "PCAN-USB"),
        T_DATA("PCI NE2K Ethernet", "NE2K"),
        T_DATA("PCI Rocker Ethernet switch device", "Rocker switch"),
        T_DATA("PL2301 USB-USB Bridge", "PL2301 USB-USB Bridge"),
        T_DATA("PL2302 USB-USB Bridge", "PL2302 USB-USB Bridge"),
        T_DATA("PL25A1 Host-Host Bridge", "PL25A1 Host-Host Bridge"),
        T_DATA("Platform Controller Hub EG20T Controller Area Network (CAN) Controller", "EG20T"),
        T_DATA("PN672TX 10/100 Ethernet", "PN672TX"),
        T_DATA("Pocket Ethernet [klsi]", "Pocket"),
        T_DATA("Prism GT 802.11b/g Adapter", "Prism GT"),
        T_DATA("PRO/100 VE Network Connection", "PRO/100 VE"),
        T_DATA("PRO/100 VM Network Connection", "PRO/100 VM"),
        T_DATA("PRO/Wireless 2200BG [Calexico2] Network Connection", "PRO/Wireless 2200BG"),
        T_DATA("PRO/Wireless 2915ABG [Calexico2] Network Connection", "PRO/Wireless 2915ABG"),
        T_DATA("PRO/Wireless 3945ABG [Golan] Network Connection", "PRO/Wireless 3945ABG"),
        T_DATA("PRO/Wireless 4965 AG or AGN [Kedron] Network Connection",
               "PRO/Wireless 4965 AG or AGN"),
        T_DATA("PRO/Wireless 5100 AGN [Shiloh] Network Connection", "PRO/Wireless 5100 AGN"),
        T_DATA("PRO/Wireless 5350 AGN [Echo Peak] Network Connection", "PRO/Wireless 5350 AGN"),
        T_DATA("PRO/Wireless LAN 2100 3B Mini PCI Adapter (Dell Latitude D800)",
               "PRO/Wireless 2100 3B Mini"),
        T_DATA("PRO/Wireless LAN 2100 3B Mini PCI Adapter (MIM2000/Centrino)",
               "PRO/Wireless 2100 3B Mini"),
        T_DATA("PRO/Wireless LAN 2100 3B Mini PCI Adapter", "PRO/Wireless 2100 3B Mini"),
        T_DATA("PRO/Wireless LAN 2100 3B Mini PCI Adapter (Samsung X10/P30 integrated WLAN)",
               "PRO/Wireless 2100 3B Mini"),
        T_DATA("PRO/Wireless LAN 2100 3B Mini PCI Adapter (Toshiba Satellite M10)",
               "PRO/Wireless 2100 3B Mini"),
        T_DATA("Psion Gold Port Ethernet", "Psion Gold Port"),
        T_DATA("PTA01 Wireless Adapter", "PTA01"),
        T_DATA("QCA6164 802.11ac Wireless Network Adapter", "QCA6164"),
        T_DATA("QCA6174 802.11ac Wireless Network Adapter", "QCA6174"),
        T_DATA("QCA8171 Gigabit Ethernet", "QCA8171"),
        T_DATA("QCA8172 Fast Ethernet", "QCA8172"),
        T_DATA("QCA9377 802.11ac Wireless Network Adapter", "QCA9377"),
        T_DATA("QCA9565 / AR9565 Wireless Network Adapter", "QCA9565 / AR9565"),
        T_DATA("QCA986x/988x 802.11ac Wireless Network Adapter", "QCA986x/988x"),
        T_DATA("QCA9887 802.11ac Wireless Network Adapter", "QCA9887"),
        T_DATA("QCA9980/9990 802.11ac Wireless Network Adapter", "QCA9980/9990"),
        T_DATA("Qualcomm HSUSB Device", "Qualcomm HSUSB"),
        T_DATA("Quectel UC20", "Quectel UC20"),
        T_DATA("QuickWLAN 802.11bg", "QuickWLAN"),
        T_DATA("R6040 MAC Controller", "R6040"),
        T_DATA("Ralink RT2770/2720 802.11b/g/n Wireless LAN Mini-USB Device", "Ralink RT2770/2720"),
        T_DATA("Ralink RT3070 802.11b/g/n Wireless Lan USB Device", "Ralink RT3070"),
        T_DATA("ReadyLink 2000", "ReadyLink 2000"),
        T_DATA("Realtek RTL8187 Wireless 802.11g 54Mbps Network Adapter", "Realtek RTL8187"),
        T_DATA("RIO 10/100 Ethernet [eri]", "RIO"),
        T_DATA("RL100-ATX 10/100", "RL100-ATX"),
        T_DATA("RL100TX Fast Ethernet", "RL100TX"),
        T_DATA("ROL/F-100 Fast Ethernet Adapter with ROL", "ROL/F-100 with ROL"),
        T_DATA("RT2070 Wireless Adapter", "RT2070"),
        T_DATA("RT2500USB Wireless Adapter", "RT2500USB"),
        T_DATA("RT2500 Wireless 802.11bg", "RT2500"),
        T_DATA("RT2501/RT2573 Wireless Adapter", "RT2501/RT2573"),
        T_DATA("RT2501USB Wireless Adapter", "RT2501USB"),
        T_DATA("RT2561/RT61 802.11g PCI", "RT2561/RT61"),
        T_DATA("RT2561/RT61 rev B 802.11g", "RT2561/RT61"),
        T_DATA("RT2570", "RT2570"),
        T_DATA("RT2570 Wireless Adapter", "RT2570"),
        T_DATA("RT2573", "RT2573"),
        T_DATA("RT2600 802.11 MIMO", "RT2600 MIMO"),
        T_DATA("RT2601/RT2671 Wireless Adapter", "RT2601/RT2671"),
        T_DATA("RT2760 Wireless 802.11n 1T/2R", "RT2760 1T/2R"),
        T_DATA("RT2770 Wireless Adapter", "RT2770"),
        T_DATA("RT2790 Wireless 802.11n 1T/2R PCIe", "RT2790 1T/2R"),
        T_DATA("RT2800 802.11n PCI", "RT2800"),
        T_DATA("RT2870/RT3070 Wireless Adapter", "RT2870/RT3070"),
        T_DATA("RT2870 Wireless Adapter", "RT2870"),
        T_DATA("RT2890 Wireless 802.11n PCIe", "RT2890"),
        T_DATA("RT3060 Wireless 802.11n 1T/1R", "RT3060 1T/1R"),
        T_DATA("RT3062 Wireless 802.11n 2T/2R", "RT3062 2T/2R"),
        T_DATA("RT3071 Wireless Adapter", "RT3071"),
        T_DATA("RT3072 Wireless Adapter", "RT3072"),
        T_DATA("RT3090 Wireless 802.11n 1T/1R PCIe", "RT3090 1T/1R"),
        T_DATA("RT3091 Wireless 802.11n 1T/2R PCIe", "RT3091 1T/2R"),
        T_DATA("RT3092 Wireless 802.11n 2T/2R PCIe", "RT3092 2T/2R"),
        T_DATA("RT3290 Wireless 802.11n 1T/1R PCIe", "RT3290 1T/1R"),
        T_DATA("RT3370 Wireless Adapter", "RT3370"),
        T_DATA("RT3572 Wireless Adapter", "RT3572"),
        T_DATA("RT3573 Wireless Adapter", "RT3573"),
        T_DATA("RT3592 PCIe Wireless Network Adapter", "RT3592"),
        T_DATA("RT3592 Wireless 802.11abgn 2T/2R PCIe", "RT3592 2T/2R"),
        T_DATA("RT5360 Wireless 802.11n 1T/1R", "RT5360 1T/1R"),
        T_DATA("RT5362 PCI 802.11n Wireless Network Adapter", "RT5362"),
        T_DATA("RT5370 Wireless Adapter", "RT5370"),
        T_DATA("RT5372 Wireless Adapter", "RT5372"),
        T_DATA("RT5390 [802.11 b/g/n 1T1R G-band PCI Express Single Chip]", "RT5390"),
        T_DATA("RT5390R 802.11bgn PCIe Wireless Network Adapter", "RT5390R"),
        T_DATA("RT5390 Wireless 802.11n 1T/1R PCIe", "RT5390 1T/1R"),
        T_DATA("RT5392 PCIe Wireless Network Adapter", "RT5392"),
        T_DATA("RT5572 Wireless Adapter", "RT5572"),
        T_DATA("RT8139 (B/C) Cardbus Fast Ethernet Adapter", "RT8139"),
        T_DATA("RTL-8029(AS)", "RTL-8029"),
        T_DATA("RTL-8100/8101L/8139 PCI Fast Ethernet Adapter", "RTL-8100/8101L/8139"),
        T_DATA("RTL8101/2/6E PCI Express Fast/Gigabit Ethernet controller", "RTL8101/2/6E"),
        T_DATA("RTL-8110SC/8169SC Gigabit Ethernet", "RTL-8110SC/8169SC"),
        T_DATA("RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller", "RTL8111/8168/8411"),
        T_DATA("RTL-8129", "RTL-8129"),
        T_DATA("RTL8139D [Realtek] PCI 10/100BaseTX ethernet adaptor", "RTL8139D"),
        T_DATA("RTL8139 Ethernet", "RTL8139"),
        T_DATA("RTL8139 [FE2000VX] CardBus Fast Ethernet Attached Port Adapter", "RTL8139"),
        T_DATA("RTL8150 Fast Ethernet Adapter", "RTL8150"),
        T_DATA("RTL8151", "RTL8151"),
        T_DATA("RTL8152 Fast Ethernet Adapter", "RTL8152"),
        T_DATA("RTL8153 Gigabit Ethernet Adapter", "RTL8153"),
        T_DATA("RTL8169 PCI Gigabit Ethernet Controller", "RTL8169"),
        T_DATA("RTL8180L 802.11b MAC", "RTL8180L"),
        T_DATA("RTL-8185 IEEE 802.11a/b/g Wireless LAN Controller", "RTL-8185"),
        T_DATA("RTL8187B Wireless 802.11g 54Mbps Network Adapter", "RTL8187B"),
        T_DATA("RTL8187B Wireless Adapter", "RTL8187B"),
        T_DATA("RTL8187SE Wireless LAN Controller", "RTL8187SE"),
        T_DATA("RTL8187 Wireless Adapter", "RTL8187"),
        T_DATA("RTL8188CE 802.11b/g/n WiFi Adapter", "RTL8188CE"),
        T_DATA("RTL8188CUS 802.11n WLAN Adapter", "RTL8188CUS"),
        T_DATA("RTL8188EE Wireless Network Adapter", "RTL8188EE"),
        T_DATA("RTL8188RU 802.11n WLAN Adapter", "RTL8188RU"),
        T_DATA("RTL8191CE PCIe Wireless Network Adapter", "RTL8191CE"),
        T_DATA("RTL8191SEvA Wireless LAN Controller", "RTL8191SEvA"),
        T_DATA("RTL8191SEvB Wireless LAN Controller", "RTL8191SEvB"),
        T_DATA("RTL8192CE PCIe Wireless Network Adapter", "RTL8192CE"),
        T_DATA("RTL8192CU 802.11n WLAN Adapter", "RTL8192CU"),
        T_DATA("RTL8192DE Wireless LAN Controller", "RTL8192DE"),
        T_DATA("RTL8192EE PCIe Wireless Network Adapter", "RTL8192EE"),
        T_DATA("RTL8192E/RTL8192SE Wireless LAN Controller", "RTL8192E/RTL8192SE"),
        T_DATA("RTL8192EU 802.11b/g/n WLAN Adapter", "RTL8192EU"),
        T_DATA("RTL8192SE Wireless LAN Controller", "RTL8192SE"),
        T_DATA("RTL81xx Fast Ethernet", "RTL81xx"),
        T_DATA("RTL81xx RealTek Ethernet", "RTL81xx RealTek"),
        T_DATA("RTL8723AE PCIe Wireless Network Adapter", "RTL8723AE"),
        T_DATA("RTL8723AU 802.11n WLAN Adapter", "RTL8723AU"),
        T_DATA("RTL8723BE PCIe Wireless Network Adapter", "RTL8723BE"),
        T_DATA("RTL8812AE 802.11ac PCIe Wireless Network Adapter", "RTL8812AE"),
        T_DATA("RTL8821AE 802.11ac PCIe Wireless Network Adapter", "RTL8821AE"),
        T_DATA("S310-CR 10GbE Single Port Adapter", "S310-CR Single Port"),
        T_DATA("S320-LP-CR 10GbE Dual Port Adapter", "S320-LP-CR"),
        T_DATA("Samsung Gobi 2000 Wireless Modem", "Samsung Gobi 2000"),
        T_DATA("SC92031 PCI Fast Ethernet Adapter", "SC92031"),
        T_DATA("SD8688 WLAN", "SD8688"),
        T_DATA("SD8786 WLAN", "SD8786"),
        T_DATA("SD8787 WLAN", "SD8787"),
        T_DATA("SD8797 WLAN", "SD8797"),
        T_DATA("SD8897 WLAN", "SD8897"),
        T_DATA("SFC4000 rev A net [Solarstorm]", "SFC4000"),
        T_DATA("SFC4000 rev B [Solarstorm]", "SFC4000"),
        T_DATA("SFC9020 10G Ethernet Controller", "SFC9020"),
        T_DATA("SFC9120 10G Ethernet Controller", "SFC9120"),
        T_DATA("SFC9120 10G Ethernet Controller (Virtual Function)", "SFC9120"),
        T_DATA("SFC9140 10/40G Ethernet Controller", "SFC9140"),
        T_DATA("SFC9140 10/40G Ethernet Controller (Virtual Function)", "SFC9140"),
        T_DATA("SFC9220 10/40G Ethernet Controller", "SFC9220"),
        T_DATA("SFC9220 10/40G Ethernet Controller (Virtual Function)", "SFC9220"),
        T_DATA("SFL9021 10GBASE-T Ethernet Controller", "SFL9021"),
        T_DATA("Shasta (Sun GEM)", "Shasta"),
        T_DATA("Siemens S30853-S1016-R107 802.11g Wireless Adapter [Intersil ISL3886]",
               "Siemens S30853-S1016-R107"),
        T_DATA("Siemens S30853-S1031-R351 802.11g Wireless Adapter [Atheros AR5523]",
               "Siemens S30853-S1031-R351"),
        T_DATA("Siemens S30853-S1038-R351 802.11g Wireless Adapter [Atheros AR5523]",
               "Siemens S30853-S1038-R351"),
        T_DATA("Siemens S30863-S1016-R107-2 802.11g Wireless Adapter [Intersil ISL3887]",
               "Siemens S30863-S1016-R107-2"),
        T_DATA("Siemens SpeedStream 100MBps Ethernet", "Siemens SpeedStream"),
        T_DATA("Sierra Wireless Gobi 3000 Modem device (MC8355)", "Sierra Gobi 3000"),
        T_DATA("SIMCom SIM5218 modem", "SIMCom SIM5218"),
        T_DATA("SiS7016 PCI Fast Ethernet Adapter", "SiS7016"),
        T_DATA("SiS900 PCI Fast Ethernet", "SiS900"),
        T_DATA("SK-9871 V2.0 Gigabit Ethernet 1000Base-ZX Adapter, PCI64, Fiber ZX/SC",
               "SK-9871 ZX/SC"),
        T_DATA("SK-9872 Gigabit Ethernet Server Adapter (SK-NET GE-ZX dual link)", "SK-9872"),
        T_DATA("SK-9Dxx Gigabit Ethernet Adapter", "SK-9Dxx"),
        T_DATA("SK-9E21D 10/100/1000Base-T Adapter, Copper RJ-45", "SK-9E21D"),
        T_DATA("SK-9E21M 10/100/1000Base-T Adapter", "SK-9E21M"),
        T_DATA("SK-9Mxx Gigabit Ethernet Adapter", "SK-9Mxx"),
        T_DATA("SK-9S21 10/100/1000Base-T Server Adapter, PCI-X, Copper RJ-45", "SK-9S21"),
        T_DATA("smartNIC 2 PnP Ethernet", "smartNIC 2"),
        T_DATA("smartNIC Ethernet [catc]", "smartNIC"),
        T_DATA("SMC2-1211TX", "SMC2-1211TX"),
        T_DATA("SMC2862W-G v1 EZ Connect 802.11g Adapter [Intersil ISL3886]",
               "SMC2862W-G EZ Connect"),
        T_DATA("SMC2862W-G v2 EZ Connect 802.11g Adapter [Intersil ISL3887]",
               "SMC2862W-G EZ Connect"),
        T_DATA("SMC2862W-G v3 EZ Connect 802.11g Adapter [Intersil ISL3887]",
               "SMC2862W-G EZ Connect"),
        T_DATA("SMC SMCWUSB-N 802.11bgn 2x2:2 Wireless Adapter [Ralink RT2870]",
               "SMC SMCWUSB-N 2x2:2"),
        T_DATA("SMCWUSB-G 802.11bg", "SMCWUSB-G"),
        T_DATA("SMCWUSBS-N2 EZ Connect N Wireless Adapter [Ralink RT2870]",
               "SMCWUSBS-N2 EZ Connect"),
        T_DATA("SMCWUSBS-N3 EZ Connect N Wireless Adapter [Ralink RT3070]",
               "SMCWUSBS-N3 EZ Connect"),
        T_DATA("SMCWUSBS-N EZ Connect N Draft 11n Wireless Adapter [Ralink RT2870]",
               "SMCWUSBS-N EZ Connect"),
        T_DATA("SMCWUSBT-G (no firmware)", "SMCWUSBT-G"),
        T_DATA("SMCWUSBT-G", "SMCWUSBT-G"),
        T_DATA("SMSC9512/9514 Fast Ethernet Adapter", "SMSC9512/9514"),
        T_DATA("SNU5600 802.11bg", "SNU5600"),
        T_DATA("SoftGate 802.11 Adapter", "SoftGate"),
        T_DATA("Sony 10Mbps Ethernet [pegasus]", "Sony"),
        T_DATA("Sony Gobi 2000 Wireless Modem", "Sony Gobi 2000"),
        T_DATA("Sony UWA-BR100 802.11abgn Wireless Adapter [Atheros AR7010+AR9280]",
               "Sony UWA-BR100"),
        T_DATA("SparkLAN WL-682 802.11bg Wireless Adapter [Intersil ISL3887]", "SparkLAN WL-682"),
        T_DATA("Speedport W 102 Stick IEEE 802.11n USB 2.0 Adapter", "Speedport W 102 Stick"),
        T_DATA("SpeedStream 10/100 Ethernet [pegasus]", "SpeedStream"),
        T_DATA("SpeedTouch 120g 802.11g Wireless Adapter [Intersil ISL3886]", "SpeedTouch 120g"),
        T_DATA("SpeedTouch 121g Wireless Dongle", "SpeedTouch 121g Dongle"),
        T_DATA("Sphairon Homelink 1202 802.11n Wireless Adapter [Atheros AR9170]",
               "Sphairon Homelink 1202"),
        T_DATA("ST201 Sundance Ethernet", "ST201 Sundance"),
        T_DATA("ST268", "ST268"),
        T_DATA("SURECOM EP-320X-S 100/10M Ethernet PCI Adapter", "SURECOM EP-320X-S"),
        T_DATA("T210 Protocol Engine", "T210 Protocol Engine"),
        T_DATA("T302 1GbE Dual Port Adapter", "T302"),
        T_DATA("T310 10GbE Single Port Adapter", "T310 Single Port"),
        T_DATA("T320 10GbE Dual Port Adapter", "T320"),
        T_DATA("T404-BT Unified Wire Ethernet Controller", "T404-BT"),
        T_DATA("T404-BT Unified Wire Ethernet Controller [VF]", "T404-BT"),
        T_DATA("T420-4082  Unified Wire Ethernet Controller", "T420-4082"),
        T_DATA("T420-4082 Unified Wire Ethernet Controller [VF]", "T420-4082"),
        T_DATA("T420-4085 SFP+ Unified Wire Ethernet Controller", "T420-4085 SFP+"),
        T_DATA("T420-4085 SFP+ Unified Wire Ethernet Controller [VF]", "T420-4085 SFP+"),
        T_DATA("T420-BCH Unified Wire Ethernet Controller", "T420-BCH"),
        T_DATA("T420-BCH Unified Wire Ethernet Controller [VF]", "T420-BCH"),
        T_DATA("T420-BT Unified Wire Ethernet Controller", "T420-BT"),
        T_DATA("T420-BT Unified Wire Ethernet Controller [VF]", "T420-BT"),
        T_DATA("T420-CR Unified Wire Ethernet Controller", "T420-CR"),
        T_DATA("T420-CR Unified Wire Ethernet Controller [VF]", "T420-CR"),
        T_DATA("T420-CX Unified Wire Ethernet Controller", "T420-CX"),
        T_DATA("T420-CX Unified Wire Ethernet Controller [VF]", "T420-CX"),
        T_DATA("T420-SO Unified Wire Ethernet Controller", "T420-SO"),
        T_DATA("T420-SO Unified Wire Ethernet Controller [VF]", "T420-SO"),
        T_DATA("T420X-4083 Unified Wire Ethernet Controller", "T420X-4083"),
        T_DATA("T420X-4083 Unified Wire Ethernet Controller [VF]", "T420X-4083"),
        T_DATA("T422-CR Unified Wire Ethernet Controller", "T422-CR"),
        T_DATA("T422-CR Unified Wire Ethernet Controller [VF]", "T422-CR"),
        T_DATA("T440-4084 Unified Wire Ethernet Controller", "T440-4084"),
        T_DATA("T440-4084 Unified Wire Ethernet Controller [VF]", "T440-4084"),
        T_DATA("T440-4086 10Gbase-T Unified Wire Ethernet Controller", "T440-4086"),
        T_DATA("T440-4086 10Gbase-T Unified Wire Ethernet Controller [VF]", "T440-4086"),
        T_DATA("T440-4088 Unified Wire Ethernet Controller", "T440-4088"),
        T_DATA("T440-4088 Unified Wire Ethernet Controller [VF]", "T440-4088"),
        T_DATA("T440-BCH Unified Wire Ethernet Controller", "T440-BCH"),
        T_DATA("T440-BCH Unified Wire Ethernet Controller [VF]", "T440-BCH"),
        T_DATA("T440-CH Unified Wire Ethernet Controller", "T440-CH"),
        T_DATA("T440-CH Unified Wire Ethernet Controller [VF]", "T440-CH"),
        T_DATA("T440-CR Unified Wire Ethernet Controller", "T440-CR"),
        T_DATA("T440-CR Unified Wire Ethernet Controller [VF]", "T440-CR"),
        T_DATA("T440F-4081 T440-FCoE Unified Wire Ethernet Controller", "T440F-4081 T440-FCoE"),
        T_DATA("T440F-4081 T440-FCoE Unified Wire Ethernet Controller [VF]",
               "T440F-4081 T440-FCoE"),
        T_DATA("T440-LP-CR Unified Wire Ethernet Controller", "T440-LP-CR"),
        T_DATA("T440-LP-CR Unified Wire Ethernet Controller [VF]", "T440-LP-CR"),
        T_DATA("T440T-4087 Unified Wire Ethernet Controller", "T440T-4087"),
        T_DATA("T440T-4087 Unified Wire Ethernet Controller [VF]", "T440T-4087"),
        T_DATA("T480-4080 T480 Unified Wire Ethernet Controller", "T480-4080 T480"),
        T_DATA("T480-4080 T480 Unified Wire Ethernet Controller [VF]", "T480-4080 T480"),
        T_DATA("T480 Unified Wire Ethernet Controller", "T480"),
        T_DATA("T480 Unified Wire Ethernet Controller [VF]", "T480"),
        T_DATA("T502-BT Unified Wire Ethernet Controller", "T502-BT"),
        T_DATA("T502-BT Unified Wire Ethernet Controller [VF]", "T502-BT"),
        T_DATA("T504-5082 Unified Wire Ethernet Controller", "T504-5082"),
        T_DATA("T504-5082 Unified Wire Ethernet Controller [VF]", "T504-5082"),
        T_DATA("T504-BT Unified Wire Ethernet Controller", "T504-BT"),
        T_DATA("T504-BT Unified Wire Ethernet Controller [VF]", "T504-BT"),
        T_DATA("T520-5089 Unified Wire Ethernet Controller", "T520-5089"),
        T_DATA("T520-5089 Unified Wire Ethernet Controller [VF]", "T520-5089"),
        T_DATA("T520-5092 Unified Wire Ethernet Controller", "T520-5092"),
        T_DATA("T520-5092 Unified Wire Ethernet Controller [VF]", "T520-5092"),
        T_DATA("T520-5097 Unified Wire Ethernet Controller", "T520-5097"),
        T_DATA("T520-5097 Unified Wire Ethernet Controller [VF]", "T520-5097"),
        T_DATA("T520-509A Unified Wire Ethernet Controller", "T520-509A"),
        T_DATA("T520-509A Unified Wire Ethernet Controller [VF]", "T520-509A"),
        T_DATA("T520-509C Unified Wire Ethernet Controller", "T520-509C"),
        T_DATA("T520-509C Unified Wire Ethernet Controller [VF]", "T520-509C"),
        T_DATA("T520-509E Unified Wire Ethernet Controller", "T520-509E"),
        T_DATA("T520-509E Unified Wire Ethernet Controller [VF]", "T520-509E"),
        T_DATA("T520-BCH Unified Wire Ethernet Controller", "T520-BCH"),
        T_DATA("T520-BCH Unified Wire Ethernet Controller [VF]", "T520-BCH"),
        T_DATA("T520-BT Unified Wire Ethernet Controller", "T520-BT"),
        T_DATA("T520-BT Unified Wire Ethernet Controller [VF]", "T520-BT"),
        T_DATA("T520-CR Unified Wire Ethernet Controller", "T520-CR"),
        T_DATA("T520-CR Unified Wire Ethernet Controller [VF]", "T520-CR"),
        T_DATA("T520-CX Unified Wire Ethernet Controller", "T520-CX"),
        T_DATA("T520-CX Unified Wire Ethernet Controller [VF]", "T520-CX"),
        T_DATA("T520-LL-CR Unified Wire Ethernet Controller", "T520-LL-CR"),
        T_DATA("T520-LL-CR Unified Wire Ethernet Controller [VF]", "T520-LL-CR"),
        T_DATA("T520-OCP-SO Unified Wire Ethernet Controller", "T520-OCP-SO"),
        T_DATA("T520-OCP-SO Unified Wire Ethernet Controller [VF]", "T520-OCP-SO"),
        T_DATA("T520-SO Unified Wire Ethernet Controller", "T520-SO"),
        T_DATA("T520-SO Unified Wire Ethernet Controller [VF]", "T520-SO"),
        T_DATA("T522-5091 Unified Wire Ethernet Controller", "T522-5091"),
        T_DATA("T522-5091 Unified Wire Ethernet Controller [VF]", "T522-5091"),
        T_DATA("T522-CR Unified Wire Ethernet Controller", "T522-CR"),
        T_DATA("T522-CR Unified Wire Ethernet Controller [VF]", "T522-CR"),
        T_DATA("T540-5080 Unified Wire Ethernet Controller", "T540-5080"),
        T_DATA("T540-5080 Unified Wire Ethernet Controller [VF]", "T540-5080"),
        T_DATA("T540-5081 Unified Wire Ethernet Controller", "T540-5081"),
        T_DATA("T540-5081 Unified Wire Ethernet Controller [VF]", "T540-5081"),
        T_DATA("T540-5083 Unified Wire Ethernet Controller", "T540-5083"),
        T_DATA("T540-5083 Unified Wire Ethernet Controller [VF]", "T540-5083"),
        T_DATA("T540-5084 Unified Wire Ethernet Controller", "T540-5084"),
        T_DATA("T540-5084 Unified Wire Ethernet Controller [VF]", "T540-5084"),
        T_DATA("T540-5090 Unified Wire Ethernet Controller", "T540-5090"),
        T_DATA("T540-5090 Unified Wire Ethernet Controller [VF]", "T540-5090"),
        T_DATA("T540-5094 Unified Wire Ethernet Controller", "T540-5094"),
        T_DATA("T540-5094 Unified Wire Ethernet Controller [VF]", "T540-5094"),
        T_DATA("T540-5095 Unified Wire Ethernet Controller", "T540-5095"),
        T_DATA("T540-5095 Unified Wire Ethernet Controller [VF]", "T540-5095"),
        T_DATA("T540-509B Unified Wire Ethernet Controller", "T540-509B"),
        T_DATA("T540-509B Unified Wire Ethernet Controller [VF]", "T540-509B"),
        T_DATA("T540-509D Unified Wire Ethernet Controller", "T540-509D"),
        T_DATA("T540-509D Unified Wire Ethernet Controller [VF]", "T540-509D"),
        T_DATA("T540-509F Unified Wire Ethernet Controller", "T540-509F"),
        T_DATA("T540-509F Unified Wire Ethernet Controller [VF]", "T540-509F"),
        T_DATA("T540-50A0 Unified Wire Ethernet Controller", "T540-50A0"),
        T_DATA("T540-50A0 Unified Wire Ethernet Controller [VF]", "T540-50A0"),
        T_DATA("T540-50A1 Unified Wire Ethernet Controller", "T540-50A1"),
        T_DATA("T540-50A1 Unified Wire Ethernet Controller [VF]", "T540-50A1"),
        T_DATA("T540-BCH Unified Wire Ethernet Controller", "T540-BCH"),
        T_DATA("T540-BCH Unified Wire Ethernet Controller [VF]", "T540-BCH"),
        T_DATA("T540-BT Unified Wire Ethernet Controller", "T540-BT"),
        T_DATA("T540-BT Unified Wire Ethernet Controller [VF]", "T540-BT"),
        T_DATA("T540-CH Unified Wire Ethernet Controller", "T540-CH"),
        T_DATA("T540-CH Unified Wire Ethernet Controller [VF]", "T540-CH"),
        T_DATA("T540-CR Unified Wire Ethernet Controller", "T540-CR"),
        T_DATA("T540-CR Unified Wire Ethernet Controller [VF]", "T540-CR"),
        T_DATA("T540-LP-CR Unified Wire Ethernet Controller", "T540-LP-CR"),
        T_DATA("T540-LP-CR Unified Wire Ethernet Controller [VF]", "T540-LP-CR"),
        T_DATA("T560-CR Unified Wire Ethernet Controller", "T560-CR"),
        T_DATA("T560-CR Unified Wire Ethernet Controller [VF]", "T560-CR"),
        T_DATA("T570-5088 Unified Wire Ethernet Controller", "T570-5088"),
        T_DATA("T570-5088 Unified Wire Ethernet Controller [VF]", "T570-5088"),
        T_DATA("T580-5085 Unified Wire Ethernet Controller", "T580-5085"),
        T_DATA("T580-5085 Unified Wire Ethernet Controller [VF]", "T580-5085"),
        T_DATA("T580-5086 Unified Wire Ethernet Controller", "T580-5086"),
        T_DATA("T580-5086 Unified Wire Ethernet Controller [VF]", "T580-5086"),
        T_DATA("T580-5087 Unified Wire Ethernet Controller", "T580-5087"),
        T_DATA("T580-5087 Unified Wire Ethernet Controller [VF]", "T580-5087"),
        T_DATA("T580-5093 Unified Wire Ethernet Controller", "T580-5093"),
        T_DATA("T580-5093 Unified Wire Ethernet Controller [VF]", "T580-5093"),
        T_DATA("T580-5096 Unified Wire Ethernet Controller", "T580-5096"),
        T_DATA("T580-5096 Unified Wire Ethernet Controller [VF]", "T580-5096"),
        T_DATA("T580-5098 Unified Wire Ethernet Controller", "T580-5098"),
        T_DATA("T580-5098 Unified Wire Ethernet Controller [VF]", "T580-5098"),
        T_DATA("T580-5099 Unified Wire Ethernet Controller", "T580-5099"),
        T_DATA("T580-5099 Unified Wire Ethernet Controller [VF]", "T580-5099"),
        T_DATA("T580-50A2 Unified Wire Ethernet Controller", "T580-50A2"),
        T_DATA("T580-50A2 Unified Wire Ethernet Controller [VF]", "T580-50A2"),
        T_DATA("T580-CHR Unified Wire Ethernet Controller", "T580-CHR"),
        T_DATA("T580-CHR Unified Wire Ethernet Controller [VF]", "T580-CHR"),
        T_DATA("T580-CR Unified Wire Ethernet Controller", "T580-CR"),
        T_DATA("T580-CR Unified Wire Ethernet Controller [VF]", "T580-CR"),
        T_DATA("T580-LP-CR Unified Wire Ethernet Controller", "T580-LP-CR"),
        T_DATA("T580-LP-CR Unified Wire Ethernet Controller [VF]", "T580-LP-CR"),
        T_DATA("T580-OCP-SO Unified Wire Ethernet Controller", "T580-OCP-SO"),
        T_DATA("T580-OCP-SO Unified Wire Ethernet Controller [VF]", "T580-OCP-SO"),
        T_DATA("T580-SO-CR Unified Wire Ethernet Controller", "T580-SO-CR"),
        T_DATA("T580-SO-CR Unified Wire Ethernet Controller [VF]", "T580-SO-CR"),
        T_DATA("T61100-OCP-SO Unified Wire Ethernet Controller", "T61100-OCP-SO"),
        T_DATA("T61100-OCP-SO Unified Wire Ethernet Controller [VF]", "T61100-OCP-SO"),
        T_DATA("T6201-BT Unified Wire Ethernet Controller", "T6201-BT"),
        T_DATA("T6201-BT Unified Wire Ethernet Controller [VF]", "T6201-BT"),
        T_DATA("T62100-6081 Unified Wire Ethernet Controller", "T62100-6081"),
        T_DATA("T62100-6081 Unified Wire Ethernet Controller [VF]", "T62100-6081"),
        T_DATA("T62100-6083 Unified Wire Ethernet Controller", "T62100-6083"),
        T_DATA("T62100-6083 Unified Wire Ethernet Controller [VF]", "T62100-6083"),
        T_DATA("T62100-CR Unified Wire Ethernet Controller", "T62100-CR"),
        T_DATA("T62100-CR Unified Wire Ethernet Controller [VF]", "T62100-CR"),
        T_DATA("T62100-LP-CR Unified Wire Ethernet Controller", "T62100-LP-CR"),
        T_DATA("T62100-LP-CR Unified Wire Ethernet Controller [VF]", "T62100-LP-CR"),
        T_DATA("T62100-OCP-SO Unified Wire Ethernet Controller", "T62100-OCP-SO"),
        T_DATA("T62100-OCP-SO Unified Wire Ethernet Controller [VF]", "T62100-OCP-SO"),
        T_DATA("T62100-SO-CR Unified Wire Ethernet Controller", "T62100-SO-CR"),
        T_DATA("T62100-SO-CR Unified Wire Ethernet Controller [VF]", "T62100-SO-CR"),
        T_DATA("T6210-BT Unified Wire Ethernet Controller", "T6210-BT"),
        T_DATA("T6210-BT Unified Wire Ethernet Controller [VF]", "T6210-BT"),
        T_DATA("T6225-6080 Unified Wire Ethernet Controller", "T6225-6080"),
        T_DATA("T6225-6080 Unified Wire Ethernet Controller [VF]", "T6225-6080"),
        T_DATA("T6225-6082 Unified Wire Ethernet Controller", "T6225-6082"),
        T_DATA("T6225-6082 Unified Wire Ethernet Controller [VF]", "T6225-6082"),
        T_DATA("T6225-CR Unified Wire Ethernet Controller", "T6225-CR"),
        T_DATA("T6225-CR Unified Wire Ethernet Controller [VF]", "T6225-CR"),
        T_DATA("T6225-LL-CR Unified Wire Ethernet Controller", "T6225-LL-CR"),
        T_DATA("T6225-LL-CR Unified Wire Ethernet Controller [VF]", "T6225-LL-CR"),
        T_DATA("T6225-OCP-SO Unified Wire Ethernet Controller", "T6225-OCP-SO"),
        T_DATA("T6225-OCP-SO Unified Wire Ethernet Controller [VF]", "T6225-OCP-SO"),
        T_DATA("T6225-SO-CR Unified Wire Ethernet Controller", "T6225-SO-CR"),
        T_DATA("T6225-SO-CR Unified Wire Ethernet Controller [VF]", "T6225-SO-CR"),
        T_DATA("T64100-6084 Unified Wire Ethernet Controller", "T64100-6084"),
        T_DATA("T64100-6084 Unified Wire Ethernet Controller [VF]", "T64100-6084"),
        T_DATA("T6425-CR Unified Wire Ethernet Controller", "T6425-CR"),
        T_DATA("T6425-CR Unified Wire Ethernet Controller [VF]", "T6425-CR"),
        T_DATA("T6425-SO-CR Unified Wire Ethernet Controller", "T6425-SO-CR"),
        T_DATA("T6425-SO-CR Unified Wire Ethernet Controller [VF]", "T6425-SO-CR"),
        T_DATA("TalkTalk SNU5630NS/05 802.11bg", "TalkTalk SNU5630NS/05"),
        T_DATA("TC902x Gigabit Ethernet", "TC902x"),
        T_DATA("T-Com Sinus 154 data II [Intersil ISL3887]", "T-Com Sinus 154 data II"),
        T_DATA("TEW-429UB 802.11bg", "TEW-429UB"),
        T_DATA("TEW-429UB C1 802.11bg", "TEW-429UB C1"),
        T_DATA("TEW-444UB EU (no firmware)", "TEW-444UB EU"),
        T_DATA("TEW-444UB EU [TRENDnet]", "TEW-444UB EU"),
        T_DATA("TEW-509UB A1 802.11abg Wireless Adapter [ZyDAS ZD1211]", "TEW-509UB A1"),
        T_DATA("TEW-645UB 802.11bgn 1x2:2 Wireless Adapter [Ralink RT2770]", "TEW-645UB"),
        T_DATA("TEW-648UBM 802.11n 150Mbps Micro Wireless N Adapter [Realtek RTL8188CUS]",
               "TEW-648UBM"),
        T_DATA("TG54USB 802.11bg", "TG54USB"),
        T_DATA("Thomson TG121N [Atheros AR9001U-(2)NG]", "Thomson TG121N"),
        T_DATA("Top Global Gobi 2000 Wireless Modem", "Top Global Gobi 2000"),
        T_DATA("TP-Link TL-WN322G v3 / TL-WN422G v2 802.11g [Atheros AR9271]",
               "TP-Link TL-WN322G / TL-WN422G"),
        T_DATA("TP-Link TL-WN821N v2 / TL-WN822N v1 802.11n [Atheros AR9170]",
               "TP-Link TL-WN821N / TL-WN822N"),
        T_DATA("TP-Link TL-WN821N v3 / TL-WN822N v2 802.11n [Atheros AR7010+AR9287]",
               "TP-Link TL-WN821N / TL-WN822N"),
        T_DATA("TrueMobile 1300 802.11g Wireless Adapter [Intersil ISL3880]", "TrueMobile 1300"),
        T_DATA("T-Sinus 154data", "T-Sinus 154data"),
        T_DATA("TTP-Monitoring Card V2.0", "TTP-Monitoring"),
        T_DATA("Turbolink UB801RE Wireless 802.11g 54Mbps Network Adapter [RTL8187]",
               "Turbolink UB801RE"),
        T_DATA("Turbolink UB801R WLAN Adapter", "Turbolink UB801R"),
        T_DATA("U2E", "U2E"),
        T_DATA("U5 802.11g Adapter", "U5"),
        T_DATA("UB81 802.11bgn", "UB81"),
        T_DATA("UB82 802.11abgn", "UB82"),
        T_DATA("Ubiquiti WiFiStation 802.11n [Atheros AR9271]", "Ubiquiti WiFiStation"),
        T_DATA("Ubiquiti WiFiStationEXT 802.11n [Atheros AR9271]", "Ubiquiti WiFiStationEXT"),
        T_DATA("UBS-10BT Ethernet [klsi]", "UBS-10BT"),
        T_DATA("UBS-10BT Ethernet", "UBS-10BT"),
        T_DATA("UC-110T 100Mbps Ethernet [pegasus]", "UC-110T"),
        T_DATA("UC-210T Ethernet", "UC-210T"),
        T_DATA("UF100 Ethernet [pegasus2]", "UF100"),
        T_DATA("UF200 Ethernet", "UF200"),
        T_DATA("ULi 1689,1573 integrated ethernet.", "ULi 1689 1573"),
        T_DATA("Ultimate N WiFi Link 5300", "Ultimate N 5300"),
        T_DATA("un2400 Gobi Wireless Modem", "un2400 Gobi"),
        T_DATA("UniNorth 2 GMAC (Sun GEM)", "UniNorth 2 GMAC"),
        T_DATA("UniNorth GMAC (Sun GEM)", "UniNorth GMAC"),
        T_DATA("UniNorth/Pangea GMAC (Sun GEM)", "UniNorth/Pangea GMAC"),
        T_DATA("UR054g 802.11g Wireless Adapter [Intersil ISL3887]", "UR054g"),
        T_DATA("UR055G 802.11bg", "UR055G"),
        T_DATA("USB1000 Gigabit Notebook Adapter", "USB1000"),
        T_DATA("USB-100N Ethernet [pegasus]", "USB-100N"),
        T_DATA("USB100TX Ethernet [pegasus]", "USB100TX"),
        T_DATA("USB100TX HomePNA Ethernet [pegasus]", "USB100TX HomePNA"),
        T_DATA("USB10TX Ethernet [pegasus]", "USB10TX"),
        T_DATA("USB10TX", "USB10TX"),
        T_DATA("USB 1.1 10/100M Fast Ethernet Adapter", NULL),
        T_DATA("USB200M 100baseTX Adapter", "USB200M 100baseTX"),
        T_DATA("USB200M 10/100 Ethernet Adapter", "USB200M"),
        T_DATA("USB 2.0 Ethernet", NULL),
        T_DATA("USB2AR Ethernet", "USB2AR"),
        T_DATA("USBcan II", "USBcan II"),
        T_DATA("USBE-100 Ethernet [pegasus2]", "USBE-100"),
        T_DATA("USBEL-100 Ethernet [pegasus]", "USBEL-100"),
        T_DATA("USB Ethernet [pegasus]", "pegasus"),
        T_DATA("USB ETT", "ETT"),
        T_DATA("USBLAN", "USBLAN"),
        T_DATA("USBLP-100 HomePNA Ethernet [pegasus]", "USBLP-100 HomePNA"),
        T_DATA("USB-N10 v2 802.11b/g/n Wireless Adapter [MediaTek MT7601U]", "USB-N10"),
        T_DATA("USB-N11 802.11n Network Adapter [Ralink RT2870]", "USB-N11"),
        T_DATA("USB-N13 802.11n Network Adapter (rev. A1) [Ralink RT3072]", "USB-N13"),
        T_DATA("USB-N13 802.11n Network Adapter (rev. B1) [Realtek RTL8192CU]", "USB-N13"),
        T_DATA("USB-N14 802.11b/g/n (2x2) Wireless Adapter [Ralink RT5372]", "USB-N14"),
        T_DATA("USB-N53 802.11abgn Network Adapter [Ralink RT3572]", "USB-N53"),
        T_DATA("USB TO Ethernet", NULL),
        T_DATA("USR5420 802.11g Adapter [Broadcom 4320 USB]", "USR5420"),
        T_DATA("USR5423 802.11bg Wireless Adapter [ZyDAS ZD1211B]", "USR5423"),
        T_DATA("USR997902 10/100/1000 Mbps PCI Network Card", "USR997902 Mbps"),
        T_DATA("VIC Ethernet NIC Dynamic", "VIC Dynamic"),
        T_DATA("VIC Ethernet NIC", "VIC"),
        T_DATA("VIC SR-IOV VF", "VIC SR-IOV VF"),
        T_DATA("Vigor530 IEEE 802.11G Adapter (ISL3880+NET2280)", "Vigor530"),
        T_DATA("Virtual media for 802.11bg", NULL),
        T_DATA("VMXNET3 Ethernet Controller", "VMXNET3"),
        T_DATA("VT6102/VT6103 [Rhine-II]", "VT6102/VT6103"),
        T_DATA("VT6105M [Rhine-III]", "VT6105M"),
        T_DATA("VT6105/VT6106S [Rhine-III]", "VT6105/VT6106S"),
        T_DATA("VT6120/VT6121/VT6122 Gigabit Ethernet Adapter", "VT6120/VT6121/VT6122"),
        T_DATA("VT82C926 [Amazon]", "VT82C926"),
        T_DATA("VT86C100A [Rhine]", "VT86C100A"),
        T_DATA("W89C840", "W89C840"),
        T_DATA("W89C940F", "W89C940F"),
        T_DATA("W89C940 misprogrammed [ne2k]", "W89C940"),
        T_DATA("W89C940", "W89C940"),
        T_DATA("WG111T (no firmware)", "WG111T"),
        T_DATA("WG111T", "WG111T"),
        T_DATA("WG111U Double 108 Mbps Wireless [Atheros AR5004X / AR5005UX]", "WG111U"),
        T_DATA("WG111U (no firmware) Double 108 Mbps Wireless [Atheros AR5004X / AR5005UX]",
               "WG111U"),
        T_DATA("WG111(v1) 54 Mbps Wireless [Intersil ISL3886]", "WG111"),
        T_DATA("WG111(v1) rev 2 54 Mbps Wireless [Intersil ISL3887]", "WG111"),
        T_DATA("WG111v2 54 Mbps Wireless [RealTek RTL8187L]", "WG111v2"),
        T_DATA("WG111v3 54 Mbps Wireless [realtek RTL8187B]", "WG111v3"),
        T_DATA("WG121(v1) 54 Mbps Wireless [Intersil ISL3886]", "WG121"),
        T_DATA("WG121(v2) 54 Mbps Wireless [Intersil ISL3886]", "WG121"),
        T_DATA("WGU-210 802.11g Adapter [Intersil ISL3886]", "WGU-210"),
        T_DATA("WHG-AGDN/US Wireless LAN Adapter", "WHG-AGDN/US"),
        T_DATA("Wi-Fi 11g adapter", NULL),
        T_DATA("WiFi Link 5100", "5100"),
        T_DATA("Wil6200 802.11ad Wireless Network Adapter", "Wil6200"),
        T_DATA("WiMAX/WiFi Link 5150", "5150"),
        T_DATA("Wireless 11n USB Adapter", "11n"),
        T_DATA("Wireless 1450 Dual-band (802.11a/b/g) Adapter [Intersil ISL3887]", "1450"),
        T_DATA("Wireless 3160", "3160"),
        T_DATA("Wireless 3165", "3165"),
        T_DATA("Wireless 7260", "7260"),
        T_DATA("Wireless 7265", "7265"),
        T_DATA("Wireless 802.11g 54Mbps Network Adapter [RTL8187]", "RTL8187"),
        T_DATA("Wireless 8260", "8260"),
        T_DATA("Wireless 8265 / 8275", "8265 / 8275"),
        T_DATA("Wireless Adapter 11g", NULL),
        T_DATA("Wireless LAN USB Mini-Card", NULL),
        T_DATA("Wireless MAXg Adapter [Broadcom 4320]", "MAXg"),
        T_DATA("Wireless Network Adapter", NULL),
        T_DATA("Wireless-N Network Adapter [Ralink RT2870]", "Ralink RT2870"),
        T_DATA("Wireless PCI Adapter RT2400 / RT2460", "RT2400 / RT2460"),
        T_DATA("WIS09ABGN LinkStick Wireless LAN Adapter", "WIS09ABGN LinkStick"),
        T_DATA("WL-113 rev 1 Wireless Network USB Adapter", "WL-113"),
        T_DATA("WL-113 rev 2 Wireless Network USB Adapter", "WL-113"),
        T_DATA("WL-117 Hi-Speed USB Adapter", "WL-117"),
        T_DATA("WL1271", "WL1271"),
        T_DATA("WL-159g 802.11bg [ZyDAS ZD1211B+AL2230]", "WL-159g"),
        T_DATA("WL-167G v1 802.11g Adapter [Ralink RT2571]", "WL-167G"),
        T_DATA("WL-167G v2 802.11g Adapter [Ralink RT2571W]", "WL-167G"),
        T_DATA("WL-168 Wireless Network Adapter 54g", "WL-168"),
        T_DATA("WL169gE 802.11g Adapter [Broadcom 4320 USB]", "WL169gE"),
        T_DATA("WL-172 Wireless Network USB Adapter 54g Turbo", "WL-172 Turbo"),
        T_DATA("WL-182 Wireless-N Network USB Card", "WL-182"),
        T_DATA("WL-188 Wireless Network 300N USB Adapter", "WL-188 300N"),
        T_DATA("WL-301 Wireless Network 300N USB Adapter", "WL-301 300N"),
        T_DATA("WL-302 Wireless Network 300N USB dongle", "WL-302 300N"),
        T_DATA("WL-315 Wireless-N USB Adapter", "WL-315"),
        T_DATA("WL-321 Wireless USB Gaming Adapter 300N", "WL-321 Gaming 300N"),
        T_DATA("WL-323 Wireless-N USB Adapter", "WL-323"),
        T_DATA("WL-324 Wireless USB Adapter 300N", "WL-324 300N"),
        T_DATA("WL-329 Wireless Dualband USB adapter 300N", "WL-329 Dualband 300N"),
        T_DATA("WL-343 Wireless USB Adapter 150N X1", "WL-343 150N X1"),
        T_DATA("WL-344 Wireless Adapter 300N X2 [Ralink RT3071]", "WL-344 300N X2"),
        T_DATA("WL-345 Wireless USB adapter 300N X3", "WL-345 300N X3"),
        T_DATA("WL-349v1 Wireless Adapter 150N 002 [Ralink RT3070]", "WL-349v1 150N 002"),
        T_DATA("WL-349v4 Wireless Micro Adapter 150N X1 [Ralink RT3370]", "WL-349v4 150N X1"),
        T_DATA("WL-352v1 Wireless USB Adapter 300N 002", "WL-352v1 300N 002"),
        T_DATA("WL-358v1 Wireless Micro USB Adapter 300N X3 002", "WL-358v1 300N X3 002"),
        T_DATA("WL-430U 802.11bg", "WL-430U"),
        T_DATA("WL532U 802.11g Adapter", "WL532U"),
        T_DATA("WL-603 Wireless Adapter", "WL-603"),
        T_DATA("WL-608 Wireless USB Adapter 54g", "WL-608"),
        T_DATA("WLA3310 Wireless Adapter [Intersil ISL3887]", "WLA3310"),
        T_DATA("WLA-4000 802.11bgn [Ralink RT3072]", "WLA-4000"),
        T_DATA("WLA-5000 802.11abgn [Ralink RT3572]", "WLA-5000"),
        T_DATA("WLA-5100", "WLA-5100"),
        T_DATA("WLI2-USB2-G54 Wireless LAN Adapter", "WLI2-USB2-G54"),
        T_DATA("WLI-U2-G54HP", "WLI-U2-G54HP"),
        T_DATA("WLI-U2-KG125S 802.11g Adapter [Broadcom 4320 USB]", "WLI-U2-KG125S"),
        T_DATA("WLI-U2-KG54-AI WLAN", "WLI-U2-KG54-AI"),
        T_DATA("WLI-U2-KG54-BB", "WLI-U2-KG54-BB"),
        T_DATA("WLI-U2-KG54L 802.11bg [ZyDAS ZD1211B]", "WLI-U2-KG54L"),
        T_DATA("WLI-U2-KG54 WLAN", "WLI-U2-KG54"),
        T_DATA("WLI-U2-KG54-YB WLAN", "WLI-U2-KG54-YB"),
        T_DATA("WLI-U2-SG54HP", "WLI-U2-SG54HP"),
        T_DATA("WLI-UC-AG300N Wireless LAN Adapter", "WLI-UC-AG300N"),
        T_DATA("WLI-UC-G300HP Wireless LAN Adapter", "WLI-UC-G300HP"),
        T_DATA("WLI-UC-G300N Wireless LAN Adapter [Ralink RT2870]", "WLI-UC-G300N"),
        T_DATA("WLI-UC-G301N Wireless LAN Adapter [Ralink RT3072]", "WLI-UC-G301N"),
        T_DATA("WLI-UC-G450 Wireless LAN Adapter", "WLI-UC-G450"),
        T_DATA("WLI-UC-GNHP Wireless LAN Adapter", "WLI-UC-GNHP"),
        T_DATA("WLI-UC-GNM2 Wireless LAN Adapter [Ralink RT3070]", "WLI-UC-GNM2"),
        T_DATA("WLI-UC-GNM Wireless LAN Adapter [Ralink RT8070]", "WLI-UC-GNM"),
        T_DATA("WLI-UC-GN Wireless LAN Adapter [Ralink RT3070]", "WLI-UC-GN"),
        T_DATA("WLI-USB-G54 802.11g Adapter [Broadcom 4320 USB]", "WLI-USB-G54"),
        T_DATA("WLM-10U1 802.11abgn Wireless Adapter [Ralink RT3572]", "WLM-10U1"),
        T_DATA("WLM-20U2/GN-1080 802.11abgn Wireless Adapter [Atheros AR7010+AR9280]",
               "WLM-20U2/GN-1080"),
        T_DATA("WLP-UC-AG300 Wireless LAN Adapter", "WLP-UC-AG300"),
        T_DATA("WM168g 802.11bg Wireless Adapter [Intersil ISL3886]", "WM168g"),
        T_DATA("WN111(v2) RangeMax Next Wireless [Atheros AR9170+AR9101]", "WN111"),
        T_DATA("WNA1000M 802.11bgn [Realtek RTL8188CUS]", "WNA1000M"),
        T_DATA("WNA1000Mv2 802.11bgn [Realtek RTL8188CUS?]", "WNA1000Mv2"),
        T_DATA("WNA1000 Wireless-N 150 [Atheros AR9170+AR9101]", "WNA1000 150"),
        T_DATA("WNA1100 Wireless-N 150 [Atheros AR9271]", "WNA1100 150"),
        T_DATA("WNA3100M(v1) Wireless-N 300 [Realtek RTL8192CU]", "WNA3100M"),
        T_DATA("WNDA3100v1 802.11abgn [Atheros AR9170+AR9104]", "WNDA3100v1"),
        T_DATA("WNDA3200 802.11abgn Wireless Adapter [Atheros AR7010+AR9280]", "WNDA3200"),
        T_DATA("WNDA4100 802.11abgn 3x3:3 [Ralink RT3573]", "WNDA4100"),
        T_DATA("WN-G150U Wireless LAN Adapter", "WN-G150U"),
        T_DATA("WN-G300U Wireless LAN Adapter", "WN-G300U"),
        T_DATA("WNGDNUS2 802.11n", "WNGDNUS2"),
        T_DATA("WN-GDN/US3 Wireless LAN Adapter", "WN-GDN/US3"),
        T_DATA("WPN111 802.11g Wireless Adapter [Atheros AR5523]", "WPN111"),
        T_DATA("WPN111 (no firmware)", "WPN111"),
        T_DATA("WPN111 RangeMax(TM) Wireless USB 2.0 Adapter", "WPN111 RangeMax"),
        T_DATA("WUA-1340", "WUA-1340"),
        T_DATA("WUA-2340 RangeBooster G Adapter(rev.A) [Atheros AR5523]", "WUA-2340 RangeBooster"),
        T_DATA("WUA-2340 RangeBooster G Adapter(rev.A) (no firmware) [Atheros AR5523]",
               "WUA-2340 RangeBooster"),
        T_DATA("WUA-2340 RangeBooster G Adapter(rev.B) [Ralink RT2070]", "WUA-2340 RangeBooster"),
        T_DATA("WUBR-177G [Ralink RT2571W]", "WUBR-177G"),
        T_DATA("WUBR-208N 802.11abgn Wireless Adapter [Ralink RT2870]", "WUBR-208N"),
        T_DATA("WUG2690 802.11bg Wireless Module [ZyDAS ZD1211+AL2230]", "WUG2690"),
        T_DATA("WUG2700", "WUG2700"),
        T_DATA("WUS-201 802.11bg", "WUS-201"),
        T_DATA("WUSB100 v1 RangePlus Wireless Network Adapter [Ralink RT2870]",
               "WUSB100 RangePlus"),
        T_DATA("WUSB100 v2 RangePlus Wireless Network Adapter [Ralink RT3070]",
               "WUSB100 RangePlus"),
        T_DATA("WUSB200 802.11g Adapter [Ralink RT2671]", "WUSB200"),
        T_DATA("WUSB54AG 802.11a/g Adapter [Intersil ISL3887]", "WUSB54AG"),
        T_DATA("WUSB54GC v1 802.11g Adapter [Ralink RT73]", "WUSB54GC"),
        T_DATA("WUSB54GC v2 802.11g Adapter [Realtek RTL8187B]", "WUSB54GC"),
        T_DATA("WUSB54GC v3 802.11g Adapter [Ralink RT2070L]", "WUSB54GC"),
        T_DATA("WUSB54GP v1 802.11g Adapter [Intersil ISL3886]", "WUSB54GP"),
        T_DATA("WUSB54GP v4.0 802.11g Adapter [Ralink RT2500USB]", "WUSB54GP v4.0"),
        T_DATA("WUSB54GR", "WUSB54GR"),
        T_DATA("WUSB54GSC v1 802.11g Adapter [Broadcom 4320 USB]", "WUSB54GSC"),
        T_DATA("WUSB54GS v1 802.11g Adapter [Broadcom 4320 USB]", "WUSB54GS"),
        T_DATA("WUSB54GS v2 802.11g Adapter [Broadcom 4320 USB]", "WUSB54GS"),
        T_DATA("WUSB54G v1 802.11g Adapter [Intersil ISL3886]", "WUSB54G"),
        T_DATA("WUSB54G v2 802.11g Adapter [Intersil ISL3887]", "WUSB54G"),
        T_DATA("WUSB54G v4 802.11g Adapter [Ralink RT2500USB]", "WUSB54G"),
        T_DATA("WUSB600N v1 Dual-Band Wireless-N Network Adapter [Ralink RT2870]",
               "WUSB600N Dual-Band"),
        T_DATA("WUSB600N v2 Dual-Band Wireless-N Network Adapter [Ralink RT3572]",
               "WUSB600N Dual-Band"),
        T_DATA("WUSBF54G 802.11bg", "WUSBF54G"),
        T_DATA("WUSBF54G v1.1 802.11bg", "WUSBF54G"),
        T_DATA("X3100 Series 10 Gigabit Ethernet PCIe", "X3100"),
        T_DATA("X540 Ethernet Controller Virtual Function", "X540 Virtual Function"),
        T_DATA("X540 Virtual Function", "X540 Virtual Function"),
        T_DATA("X550 Virtual Function", "X550 Virtual Function"),
        T_DATA("X552 Virtual Function", "X552 Virtual Function"),
        T_DATA("X553 Virtual Function", "X553 Virtual Function"),
        T_DATA("X722 Virtual Function", "X722 Virtual Function"),
        T_DATA("Xframe 10-Gigabit Ethernet PCI-X", "Xframe"),
        T_DATA("Xframe II 10-Gigabit Ethernet PCI-X 2.0", "Xframe II 2.0"),
        T_DATA("XG-300 802.11b Adapter", "XG-300"),
        T_DATA("XG-703A 802.11g Wireless Adapter [Intersil ISL3887]", "XG-703A"),
        T_DATA("XG-705A 802.11g Wireless Adapter [Intersil ISL3887]", "XG-705A"),
        T_DATA("XG-760A 802.11bg", "XG-760A"),
        T_DATA("XG-76NA 802.11bg", "XG-76NA"),
        T_DATA("XG Mgmt", "XG Mgmt"),
        T_DATA("Xircom PGUNET USB-USB Bridge", "Xircom PGUNET USB-USB Bridge"),
        T_DATA("XL710/X710 Virtual Function", "XL710/X710 Virtual Function"),
        T_DATA("XX1", "XX1"),
        T_DATA("XX2", "XX2"),
        T_DATA("XX4", "XX4"),
        T_DATA("XX5", "XX5"),
        T_DATA("XX6", "XX6"),
        T_DATA("XX7", "XX7"),
        T_DATA("XX9", "XX9"),
        T_DATA("Yellowfin G-NIC gigabit ethernet", "Yellowfin"),
        T_DATA("YP3X00 PDA", "YP3X00"),
        T_DATA("Yukon Optima 88E8059 [PCIe Gigabit Ethernet Controller with AVB]",
               "Yukon Optima 88E8059"),
        T_DATA("Zaurus A-300", "Zaurus A-300"),
        T_DATA("Zaurus C-700 PDA", "Zaurus C-700"),
        T_DATA("Zaurus C-750/C-760/C-860/SL-C3000 PDA", "Zaurus C-750/C-760/C-860/SL-C3000"),
        T_DATA("Zaurus C-860 PDA", "Zaurus C-860"),
        T_DATA("Zaurus SL-5000D/SL-5500 PDA", "Zaurus SL-5000D/SL-5500"),
        T_DATA("Zaurus SL-6000", "Zaurus SL-6000"),
        T_DATA("Zaurus SL-B500/SL-5600 PDA", "Zaurus SL-B500/SL-5600"),
        T_DATA("ZD1211 802.11b/g Wireless Adapter", "ZD1211"),
        T_DATA("ZD1211 802.11g", "ZD1211"),
        T_DATA("ZD1211B 802.11g", "ZD1211B"),
        T_DATA("ZD1211B", "ZD1211B"),
        T_DATA("ZD1221 802.11n", "ZD1221"),
        T_DATA("Zoom 4410 Wireless-G [Intersil ISL3887]", "Zoom 4410"),
        T_DATA("ZT6688 Fast Ethernet Adapter", "ZT6688"),
        T_DATA("ZyAIR AG-225H v2 802.11bg", "ZyAIR AG-225H"),
        T_DATA("ZyAIR G-202 802.11bg", "ZyAIR G-202"),
        T_DATA("ZyAIR G-220 802.11bg", "ZyAIR G-220"),
        T_DATA("ZyAIR G-220F 802.11bg", "ZyAIR G-220F"),
    };

    _test_fixup_string(data, G_N_ELEMENTS(data), nm_utils_fixup_product_string);
}

/*****************************************************************************/

static int
_memfd_create(const char *name)
{
#if defined(HAVE_DECL_MEMFD_CREATE) && HAVE_DECL_MEMFD_CREATE
    return memfd_create(name, MFD_CLOEXEC);
#endif
    return -1;
}

typedef struct {
    const char *key;
    const char *val;
} ReadVpnDetailData;

#define READ_VPN_DETAIL_DATA(...) ((ReadVpnDetailData[]){__VA_ARGS__})

static gboolean
_do_read_vpn_details_impl1(const char *             file,
                           int                      line,
                           int                      memfd,
                           char *                   mem,
                           gsize                    len,
                           const ReadVpnDetailData *expected_data,
                           guint                    expected_data_len,
                           const ReadVpnDetailData *expected_secrets,
                           guint                    expected_secrets_len)
{
    gssize             written;
    off_t              lseeked;
    gs_unref_hashtable GHashTable *data    = NULL;
    gs_unref_hashtable GHashTable *secrets = NULL;

    written = write(memfd, mem, len);
    g_assert_cmpint(written, ==, (gssize) len);

    lseeked = lseek(memfd, 0, SEEK_SET);
    g_assert_cmpint(lseeked, ==, 0);

    if (!nm_vpn_service_plugin_read_vpn_details(memfd, &data, &secrets)) {
        g_assert(!data);
        g_assert(!secrets);
        g_assert_cmpint(expected_data_len, ==, 0);
        g_assert_cmpint(expected_secrets_len, ==, 0);
        return TRUE;
    }

#define _assert_hash(hash, expected, expected_len)                                            \
    G_STMT_START                                                                              \
    {                                                                                         \
        GHashTable *             _hash         = (hash);                                      \
        guint                    _expected_len = (expected_len);                              \
        const ReadVpnDetailData *_expected     = (expected);                                  \
        GHashTableIter           _iter;                                                       \
        const char *             _k, *_v;                                                     \
        guint                    _i;                                                          \
                                                                                              \
        g_assert(_hash);                                                                      \
                                                                                              \
        g_hash_table_iter_init(&_iter, _hash);                                                \
        while (g_hash_table_iter_next(&_iter, (gpointer *) &_k, (gpointer *) &_v)) {          \
            for (_i = 0; _i < _expected_len; _i++) {                                          \
                if (nm_streq(_expected[_i].key, _k))                                          \
                    break;                                                                    \
            }                                                                                 \
            if (_i >= _expected_len)                                                          \
                g_error("%s:%d: hash '%s' contains unexpected data key '%s' with value '%s'", \
                        file,                                                                 \
                        line,                                                                 \
                        G_STRINGIFY(hash),                                                    \
                        _k,                                                                   \
                        _v);                                                                  \
        }                                                                                     \
                                                                                              \
        for (_i = 0; _i < _expected_len; _i++) {                                              \
            const ReadVpnDetailData *_d = &_expected[_i];                                     \
                                                                                              \
            g_assert(_d->key);                                                                \
            g_assert(_d->val);                                                                \
            _v = g_hash_table_lookup(_hash, _d->key);                                         \
            if (!nm_streq0(_v, _d->val))                                                      \
                g_error("%s:%d: hash '%s' contains data key '%s' with value %s%s%s but we "   \
                        "expected '%s'",                                                      \
                        file,                                                                 \
                        line,                                                                 \
                        G_STRINGIFY(hash),                                                    \
                        _d->key,                                                              \
                        NM_PRINT_FMT_QUOTE_STRING(_v),                                        \
                        _d->val);                                                             \
        }                                                                                     \
                                                                                              \
        g_assert_cmpint(g_hash_table_size(_hash), ==, _expected_len);                         \
    }                                                                                         \
    G_STMT_END

    _assert_hash(data, expected_data, expected_data_len);
    _assert_hash(secrets, expected_secrets, expected_secrets_len);

#undef _assert_hash
    return TRUE;
}

#define _do_read_vpn_details_impl0(str,                                          \
                                   expected_data,                                \
                                   expected_data_len,                            \
                                   expected_secrets,                             \
                                   expected_secrets_len,                         \
                                   pre_setup_cmd)                                \
    G_STMT_START                                                                 \
    {                                                                            \
        nm_auto_close int _memfd = _memfd_create("libnm-test-read-vpn-details"); \
                                                                                 \
        if (_memfd < 0)                                                          \
            g_test_skip("cannot create memfd");                                  \
        else {                                                                   \
            {                                                                    \
                pre_setup_cmd;                                                   \
            }                                                                    \
            _do_read_vpn_details_impl1(__FILE__,                                 \
                                       __LINE__,                                 \
                                       _memfd,                                   \
                                       "" str "",                                \
                                       NM_STRLEN(str),                           \
                                       expected_data,                            \
                                       expected_data_len,                        \
                                       expected_secrets,                         \
                                       expected_secrets_len);                    \
        }                                                                        \
    }                                                                            \
    G_STMT_END

#define _do_read_vpn_details_empty(str) _do_read_vpn_details_impl0(str, NULL, 0, NULL, 0, {})

#define _do_read_vpn_details(str, expected_data, expected_secrets, pre_setup_cmd) \
    _do_read_vpn_details_impl0(str,                                               \
                               expected_data,                                     \
                               G_N_ELEMENTS(expected_data),                       \
                               expected_secrets,                                  \
                               G_N_ELEMENTS(expected_secrets),                    \
                               pre_setup_cmd)

static void
test_nm_vpn_service_plugin_read_vpn_details(void)
{
    _do_read_vpn_details_empty("");
    _do_read_vpn_details_empty("hallo");
    _do_read_vpn_details_empty("DONE");
    _do_read_vpn_details_empty("DONE\n");
    _do_read_vpn_details_empty("DONE\0");
    _do_read_vpn_details_empty("\0DONE\0");

    _do_read_vpn_details(""
                         "DATA_KEY=some-key\n"
                         "DATA_VAL=string\n"
                         "\n"
                         "DATA_KEY=some-other-key\n"
                         "DATA_VAL=val2\n"
                         "\n"
                         "SECRET_KEY=some-secret\n"
                         "SECRET_VAL=val3\n"
                         "\n"
                         "DONE\n"
                         "\n"
                         "",
                         READ_VPN_DETAIL_DATA({"some-key", "string"}, {"some-other-key", "val2"}, ),
                         READ_VPN_DETAIL_DATA({"some-secret", "val3"}, ), );

    _do_read_vpn_details(""
                         "DATA_KEY=some-key\n"
                         "DATA_VAL=string\n"
                         "DONE\n",
                         READ_VPN_DETAIL_DATA({"some-key", "string"}, ),
                         READ_VPN_DETAIL_DATA(), );

    _do_read_vpn_details(
        ""
        "DATA_KEY=some-key\n"
        "DATA_VAL=string\n"
        "=continued after a line break\n"
        "SECRET_KEY=key names\n"
        "=can have\n"
        "=continuations too\n"
        "bogus1=\n"
        "SECRET_VAL=value\n"
        "bogus=value\n"
        "bogus=\n"
        "DATA_VAL=x\n"
        "DATA_KEY=\n"
        "DATA_VAL=\n"
        "DATA_VAL=y\n"
        "DATA_KEY=y\n"
        "DATA_KEY=y\n"
        "DATA_KEY=z\n"
        "SECRET_KEY=s1\n"
        "DATA_VAL=z\n"
        "SECRET_VAL=S1\n"
        "\n"
        "DONE\n"
        "",
        READ_VPN_DETAIL_DATA({"some-key", "string\ncontinued after a line break"}, ),
        READ_VPN_DETAIL_DATA({"key names\ncan have\ncontinuations too", "value"}, ),
        NMTST_EXPECT_LIBNM_WARNING("DATA_VAL= not preceded by DATA_KEY="));

    _do_read_vpn_details(
        ""
        "DATA_KEY=some-key\n"
        "DATA_VAL=string\n"
        "=continued after a line break\n"
        "SECRET_KEY=key names\n"
        "=can have\n"
        "=continuations too\n"
        "SECRET_VAL=value\n"
        "",
        READ_VPN_DETAIL_DATA({"some-key", "string\ncontinued after a line break"}, ),
        READ_VPN_DETAIL_DATA({"key names\ncan have\ncontinuations too", "value"}, ), );

    _do_read_vpn_details(
        ""
        "DATA_KEY=some-key\n"
        "DATA_VAL=string\n"
        "\n"
        "DATA_KEY=some\n"
        "=key-2\n"
        "DATA_VAL=val2\n"
        "\n"
        "DATA_KEY=key3\0"
        "=key-2\n"
        "DATA_VAL=val3\n"
        "\n"
        "SECRET_KEY=some-secret\n"
        "SECRET_VAL=val3\n"
        "\n"
        "SECRET_KEY=\n"
        "SECRET_VAL=val3\n"
        "\n"
        "SECRET_KEY=keyx\n"
        "SECRET_VAL=\n"
        "\n"
        "SECRET_KEY=ke\xc0yx\n"
        "SECRET_VAL=inval\n"
        "\n"
        "SECRET_KEY=key-inval\n"
        "SECRET_VAL=in\xc1val\n"
        "\n"
        "DONE\n"
        "\n"
        "",
        READ_VPN_DETAIL_DATA({"some\nkey-2", "val2"}, {"some-key", "string"}, {"key3", "val3"}, ),
        READ_VPN_DETAIL_DATA({"some-secret", "val3"},
                             {"", "val3"},
                             {"keyx", ""},
                             {"ke\xc0yx", "inval"},
                             {"key-inval", "in\xc1val"}, ), );
}

/*****************************************************************************/

static void
test_types(void)
{
#define G(get_type_fcn)           \
    ({                            \
        GType get_type_fcn(void); \
                                  \
        get_type_fcn;             \
    })
    GType (*get_type_fcns[])(void) = {
        G(nm_802_11_ap_flags_get_type),
        G(nm_802_11_ap_security_flags_get_type),
        G(nm_802_11_mode_get_type),
        G(nm_access_point_get_type),
        G(nm_activation_state_flags_get_type),
        G(nm_active_connection_get_type),
        G(nm_active_connection_state_get_type),
        G(nm_active_connection_state_reason_get_type),
        G(nm_agent_manager_error_get_type),
        G(nm_bluetooth_capabilities_get_type),
        G(nm_bridge_vlan_get_type),
        G(nm_capability_get_type),
        G(nm_checkpoint_create_flags_get_type),
        G(nm_checkpoint_get_type),
        G(nm_client_error_get_type),
        G(nm_client_get_type),
        G(nm_client_permission_get_type),
        G(nm_client_permission_result_get_type),
        G(nm_connection_error_get_type),
        G(nm_connection_get_type),
        G(nm_connection_multi_connect_get_type),
        G(nm_connection_serialization_flags_get_type),
        G(nm_connectivity_state_get_type),
        G(nm_crypto_error_get_type),
        G(nm_device_6lowpan_get_type),
        G(nm_device_adsl_get_type),
        G(nm_device_bond_get_type),
        G(nm_device_bridge_get_type),
        G(nm_device_bt_get_type),
        G(nm_device_capabilities_get_type),
        G(nm_device_dummy_get_type),
        G(nm_device_error_get_type),
        G(nm_device_ethernet_get_type),
        G(nm_device_generic_get_type),
        G(nm_device_get_type),
        G(nm_device_infiniband_get_type),
        G(nm_device_ip_tunnel_get_type),
        G(nm_device_macsec_get_type),
        G(nm_device_macvlan_get_type),
        G(nm_device_modem_capabilities_get_type),
        G(nm_device_modem_get_type),
        G(nm_device_olpc_mesh_get_type),
        G(nm_device_ovs_bridge_get_type),
        G(nm_device_ovs_interface_get_type),
        G(nm_device_ovs_port_get_type),
        G(nm_device_ppp_get_type),
        G(nm_device_state_get_type),
        G(nm_device_state_reason_get_type),
        G(nm_device_team_get_type),
        G(nm_device_tun_get_type),
        G(nm_device_type_get_type),
        G(nm_device_vlan_get_type),
        G(nm_device_vxlan_get_type),
        G(nm_device_wifi_capabilities_get_type),
        G(nm_device_wifi_get_type),
        G(nm_device_wifi_p2p_get_type),
        G(nm_device_wimax_get_type),
        G(nm_device_wireguard_get_type),
        G(nm_device_wpan_get_type),
        G(nm_dhcp4_config_get_type),
        G(nm_dhcp6_config_get_type),
        G(nm_dhcp_config_get_type),
        G(nm_dns_entry_get_type),
        G(nm_ip4_config_get_type),
        G(nm_ip6_config_get_type),
        G(nm_ip_address_get_type),
        G(nm_ip_config_get_type),
        G(nm_ip_route_get_type),
        G(nm_ip_routing_rule_as_string_flags_get_type),
        G(nm_ip_routing_rule_get_type),
        G(nm_ip_tunnel_flags_get_type),
        G(nm_ip_tunnel_mode_get_type),
        G(nm_lldp_neighbor_get_type),
        G(nm_manager_error_get_type),
        G(nm_manager_reload_flags_get_type),
        G(nm_metered_get_type),
        G(nm_object_get_type),
        G(nm_remote_connection_get_type),
        G(nm_secret_agent_capabilities_get_type),
        G(nm_secret_agent_error_get_type),
        G(nm_secret_agent_get_secrets_flags_get_type),
        G(nm_secret_agent_old_get_type),
        G(nm_setting_6lowpan_get_type),
        G(nm_setting_802_1x_auth_flags_get_type),
        G(nm_setting_802_1x_ck_format_get_type),
        G(nm_setting_802_1x_ck_scheme_get_type),
        G(nm_setting_802_1x_get_type),
        G(nm_setting_adsl_get_type),
        G(nm_setting_bluetooth_get_type),
        G(nm_setting_bond_get_type),
        G(nm_setting_bridge_get_type),
        G(nm_setting_bridge_port_get_type),
        G(nm_setting_cdma_get_type),
        G(nm_setting_compare_flags_get_type),
        G(nm_setting_connection_autoconnect_slaves_get_type),
        G(nm_setting_connection_get_type),
        G(nm_setting_connection_lldp_get_type),
        G(nm_setting_connection_llmnr_get_type),
        G(nm_setting_connection_mdns_get_type),
        G(nm_setting_dcb_flags_get_type),
        G(nm_setting_dcb_get_type),
        G(nm_setting_diff_result_get_type),
        G(nm_setting_dummy_get_type),
        G(nm_setting_ethtool_get_type),
        G(nm_setting_generic_get_type),
        G(nm_setting_get_type),
        G(nm_setting_gsm_get_type),
        G(nm_setting_infiniband_get_type),
        G(nm_setting_ip4_config_get_type),
        G(nm_setting_ip6_config_addr_gen_mode_get_type),
        G(nm_setting_ip6_config_get_type),
        G(nm_setting_ip6_config_privacy_get_type),
        G(nm_setting_ip_config_get_type),
        G(nm_setting_ip_tunnel_get_type),
        G(nm_setting_mac_randomization_get_type),
        G(nm_setting_macsec_get_type),
        G(nm_setting_macsec_mode_get_type),
        G(nm_setting_macsec_validation_get_type),
        G(nm_setting_macvlan_get_type),
        G(nm_setting_macvlan_mode_get_type),
        G(nm_setting_match_get_type),
        G(nm_setting_olpc_mesh_get_type),
        G(nm_setting_ovs_bridge_get_type),
        G(nm_setting_ovs_dpdk_get_type),
        G(nm_setting_ovs_interface_get_type),
        G(nm_setting_ovs_patch_get_type),
        G(nm_setting_ovs_port_get_type),
        G(nm_setting_ppp_get_type),
        G(nm_setting_pppoe_get_type),
        G(nm_setting_proxy_get_type),
        G(nm_setting_proxy_method_get_type),
        G(nm_settings_add_connection2_flags_get_type),
        G(nm_settings_connection_flags_get_type),
        G(nm_setting_secret_flags_get_type),
        G(nm_setting_serial_get_type),
        G(nm_setting_serial_parity_get_type),
        G(nm_settings_error_get_type),
        G(nm_setting_sriov_get_type),
        G(nm_settings_update2_flags_get_type),
        G(nm_setting_tc_config_get_type),
        G(nm_setting_team_get_type),
        G(nm_setting_team_port_get_type),
        G(nm_setting_tun_get_type),
        G(nm_setting_tun_mode_get_type),
        G(nm_setting_user_get_type),
        G(nm_setting_vlan_get_type),
        G(nm_setting_vpn_get_type),
        G(nm_setting_vxlan_get_type),
        G(nm_setting_wifi_p2p_get_type),
        G(nm_setting_wimax_get_type),
        G(nm_setting_wired_get_type),
        G(nm_setting_wired_wake_on_lan_get_type),
        G(nm_setting_wireguard_get_type),
        G(nm_setting_wireless_get_type),
        G(nm_setting_wireless_powersave_get_type),
        G(nm_setting_wireless_security_fils_get_type),
        G(nm_setting_wireless_security_get_type),
        G(nm_setting_wireless_security_pmf_get_type),
        G(nm_setting_wireless_security_wps_method_get_type),
        G(nm_setting_wireless_wake_on_wlan_get_type),
        G(nm_setting_wpan_get_type),
        G(nm_simple_connection_get_type),
        G(nm_sriov_vf_get_type),
        G(nm_sriov_vf_vlan_protocol_get_type),
        G(nm_state_get_type),
        G(nm_tc_action_get_type),
        G(nm_tc_qdisc_get_type),
        G(nm_tc_tfilter_get_type),
        G(nm_team_link_watcher_arp_ping_flags_get_type),
        G(nm_team_link_watcher_get_type),
        G(nm_ternary_get_type),
        G(nm_utils_security_type_get_type),
        G(nm_vlan_flags_get_type),
        G(nm_vlan_priority_map_get_type),
        G(nm_vpn_connection_get_type),
        G(nm_vpn_connection_state_get_type),
        G(nm_vpn_connection_state_reason_get_type),
        G(nm_vpn_editor_get_type),
        G(nm_vpn_editor_plugin_capability_get_type),
        G(nm_vpn_editor_plugin_get_type),
        G(nm_vpn_plugin_error_get_type),
        G(nm_vpn_plugin_failure_get_type),
        G(nm_vpn_plugin_info_get_type),
        G(nm_vpn_plugin_old_get_type),
        G(nm_vpn_service_plugin_get_type),
        G(nm_vpn_service_state_get_type),
        G(nm_wep_key_type_get_type),
        G(nm_wifi_p2p_peer_get_type),
        G(nm_wimax_nsp_get_type),
        G(nm_wimax_nsp_network_type_get_type),
        G(nm_wireguard_peer_get_type),
    };
    guint i_type;

    for (i_type = 0; i_type < G_N_ELEMENTS(get_type_fcns); i_type++) {
        nm_auto_unref_gtypeclass GObjectClass *klass_unref = NULL;
        GType                                  gtype       = (get_type_fcns[i_type])();
        GObjectClass *                         klass;

        g_assert(g_str_has_prefix(g_type_name(gtype), "NM"));

        if (G_TYPE_IS_INTERFACE(gtype)) {
            if (!NM_IN_STRSET(g_type_name(gtype),
                              "NMConnection",
                              "NMVpnEditor",
                              "NMVpnEditorPlugin"))
                g_error("unexpected interface type %s", g_type_name(gtype));
            continue;
        }

        if (g_type_is_a(gtype, G_TYPE_BOXED))
            continue;

        /* We only test parts of the types, and avoid initializing all the types.
         * That is so that other unit tests in this process randomly run with either
         * the class instance already initialized or not. */
        if ((nmtst_get_rand_uint() % 5) == 0) {
            klass = (klass_unref = g_type_class_ref(gtype));
            g_assert(klass);
        } else {
            klass = g_type_class_peek(gtype);
            if (!klass)
                continue;
        }

        if (g_type_is_a(gtype, G_TYPE_ENUM))
            continue;

        if (g_type_is_a(gtype, G_TYPE_FLAGS))
            continue;

        g_assert(g_type_is_a(gtype, G_TYPE_OBJECT));
        g_assert(G_IS_OBJECT_CLASS(klass));
    }
}

/*****************************************************************************/

static void
test_nml_dbus_meta(void)
{
    const NMLDBusMetaIface *   meta_iface;
    const NMLDBusMetaProperty *meta_property;
    guint                      prop_idx;
    gsize                      i, j;
    guint                      l, m;

    for (i = 0; i < G_N_ELEMENTS(_nml_dbus_meta_ifaces); i++) {
        const NMLDBusMetaIface * mif                       = _nml_dbus_meta_ifaces[i];
        nm_auto_unref_gtypeclass GObjectClass *klass_unref = NULL;
        GObjectClass *                         klass;
        GType                                  gtype;

#define COMMON_PREFIX "org.freedesktop.NetworkManager"

        g_assert(mif);
        g_assert(mif->dbus_iface_name);
        g_assert(g_str_has_prefix(mif->dbus_iface_name, COMMON_PREFIX)
                 && !g_str_has_suffix(mif->dbus_iface_name, ".")
                 && NM_IN_SET(mif->dbus_iface_name[NM_STRLEN(COMMON_PREFIX)], '\0', '.'));
        for (j = i + 1; j < G_N_ELEMENTS(_nml_dbus_meta_ifaces); j++)
            g_assert(mif != _nml_dbus_meta_ifaces[j]);
        if (i > 0) {
            if (strcmp(_nml_dbus_meta_ifaces[i - 1]->dbus_iface_name, mif->dbus_iface_name) >= 0) {
                g_error("meta-ifaces are not properly sorted: [%zu] \"%s\" should be after [%zu] "
                        "\"%s\"",
                        i - 1,
                        _nml_dbus_meta_ifaces[i - 1]->dbus_iface_name,
                        i,
                        mif->dbus_iface_name);
            }
        }

        g_assert((mif->n_dbus_properties > 0) == (!!mif->dbus_properties));

        if (mif->interface_prio == NML_DBUS_META_INTERFACE_PRIO_NONE) {
            g_assert(!mif->get_type_fcn);
            g_assert(!mif->obj_properties);
            g_assert(mif->n_obj_properties == 0);
            g_assert(!mif->obj_properties_reverse_idx);
            if (!NM_IN_STRSET(mif->dbus_iface_name,
                              NM_DBUS_INTERFACE_AGENT_MANAGER,
                              NM_DBUS_INTERFACE_DEVICE_STATISTICS,
                              NM_DBUS_INTERFACE_DEVICE_VETH))
                g_error("D-Bus interface \"%s\" is unexpectedly empty", mif->dbus_iface_name);
            if (mif->n_dbus_properties == 0)
                continue;
            gtype = G_TYPE_NONE;
            klass = NULL;
            goto check_dbus_properties;
        }

        g_assert(NM_IN_SET((NMLDBusMetaInteracePrio) mif->interface_prio,
                           NML_DBUS_META_INTERFACE_PRIO_NMCLIENT,
                           NML_DBUS_META_INTERFACE_PRIO_PARENT_TYPE,
                           NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_10,
                           NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_20,
                           NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30));

        g_assert(mif->get_type_fcn);
        gtype = mif->get_type_fcn();
        g_assert(g_type_is_a(gtype, G_TYPE_OBJECT));

        if (mif->interface_prio == NML_DBUS_META_INTERFACE_PRIO_NMCLIENT)
            g_assert(gtype == NM_TYPE_CLIENT);
        else
            g_assert(g_type_is_a(gtype, NM_TYPE_OBJECT));

        /* We only test parts of the types, and avoid initializing all the types.
         * That is so that other unit tests in this process randomly run with either
         * the class instance already initialized or not. */
        if ((nmtst_get_rand_uint() % 5) == 0) {
            klass = (klass_unref = g_type_class_ref(gtype));
            g_assert(klass);
        } else
            klass = g_type_class_peek(gtype);

        if (klass) {
            if (NM_IS_OBJECT_CLASS(klass)) {
                NMObjectClass *nm_object_class = NM_OBJECT_CLASS(klass);

                if (nm_object_class->property_o_info || nm_object_class->property_ao_info) {
                    int ii;

                    for (ii = 0; ii < 2; ii++) {
                        const _NMObjectClassFieldInfo *p_prev = NULL;
                        const _NMObjectClassFieldInfo *p0     = ii == 0
                                                                    ? nm_object_class->property_o_info
                                                                    : nm_object_class->property_ao_info;
                        const _NMObjectClassFieldInfo *p;

                        for (p = p0; p; p = p->parent) {
                            GType          parent_gtype;
                            NMObjectClass *parent_klass;

                            g_assert(p->num > 0);
                            g_assert(NM_IS_OBJECT_CLASS(p->klass));
                            g_assert(g_type_is_a(gtype, G_TYPE_FROM_CLASS(p->klass)));
                            if (ii == 0)
                                g_assert(p->klass->property_o_info == p);
                            else
                                g_assert(p->klass->property_ao_info == p);
                            g_assert_cmpint(p->klass->priv_ptr_offset, >, 0);
                            if (p_prev) {
                                g_assert(g_type_is_a(G_TYPE_FROM_CLASS(p_prev->klass),
                                                     G_TYPE_FROM_CLASS(p->klass)));
                                g_assert(p_prev->klass != p->klass);
                                g_assert_cmpint(p_prev->klass->priv_ptr_offset,
                                                >,
                                                p->klass->priv_ptr_offset);
                                g_assert_cmpint(p->klass->priv_ptr_indirect, ==, TRUE);
                            }

                            parent_gtype = g_type_parent(G_TYPE_FROM_CLASS(p->klass));
                            g_assert(g_type_is_a(parent_gtype, NM_TYPE_OBJECT));
                            parent_klass = g_type_class_peek(parent_gtype);
                            g_assert(NM_IS_OBJECT_CLASS(parent_klass));
                            if (parent_gtype == NM_TYPE_OBJECT) {
                                g_assert_cmpint(parent_klass->priv_ptr_offset, ==, 0);
                                g_assert_cmpint(parent_klass->priv_ptr_indirect, ==, FALSE);
                                g_assert(!p->parent);
                            } else {
                                if (parent_klass->priv_ptr_offset == 0) {
                                    g_assert(!parent_klass->property_o_info);
                                    g_assert(!parent_klass->property_ao_info);
                                    g_assert_cmpint(parent_klass->priv_ptr_indirect, ==, FALSE);
                                    g_assert(!p->parent);
                                } else if (p->klass->priv_ptr_offset
                                           == parent_klass->priv_ptr_offset) {
                                    g_assert(p->klass->property_o_info
                                             == parent_klass->property_o_info);
                                    g_assert(p->klass->property_ao_info
                                             == parent_klass->property_ao_info);
                                    g_assert(p->klass->priv_ptr_indirect
                                             == parent_klass->priv_ptr_indirect);
                                } else {
                                    g_assert_cmpint(parent_klass->priv_ptr_offset, >, 0);
                                    g_assert_cmpint(parent_klass->priv_ptr_offset,
                                                    <,
                                                    p->klass->priv_ptr_offset);
                                    g_assert_cmpint(parent_klass->priv_ptr_indirect, ==, TRUE);
                                    g_assert(p->klass->property_o_info
                                                 != parent_klass->property_o_info
                                             || p->klass->property_ao_info
                                                    != parent_klass->property_ao_info);
                                }
                            }

                            p_prev = p;
                        }
                    }

                    g_assert_cmpint(nm_object_class->priv_ptr_offset, >, 0);
                } else {
                    g_assert_cmpint(nm_object_class->priv_ptr_offset, ==, 0);
                    g_assert_cmpint(nm_object_class->priv_ptr_indirect, ==, FALSE);
                }

            } else
                g_assert(NM_IS_CLIENT_CLASS(klass));
        }

        if (!mif->obj_properties) {
            g_assert_cmpint(mif->n_obj_properties, ==, 0);
            g_assert(!mif->obj_properties_reverse_idx);
        } else {
            g_assert(mif->obj_properties);
            g_assert(mif->obj_properties[0] == 0);
            g_assert_cmpint(mif->n_obj_properties, >, 1);
            if (klass) {
                for (l = 1; l < mif->n_obj_properties; l++) {
                    const GParamSpec *sp = mif->obj_properties[l];

                    g_assert(sp);
                    g_assert(sp->name);
                    g_assert(strlen(sp->name) > 0);
                }
            }

            g_assert(mif->obj_properties_reverse_idx);
            if (klass) {
                g_assert(mif->obj_properties_reverse_idx[0] == 0xFFu);
                for (l = 0; l < mif->n_obj_properties; l++) {
                    guint8 ridx = mif->obj_properties_reverse_idx[l];

                    if (ridx != 0xFFu) {
                        g_assert_cmpint(ridx, <=, mif->n_dbus_properties);
                        for (m = l + 1; m < mif->n_obj_properties; m++)
                            g_assert_cmpint(ridx, !=, mif->obj_properties_reverse_idx[m]);
                    }
                }
            }
        }

check_dbus_properties:
        for (l = 0; l < mif->n_dbus_properties; l++) {
            const NMLDBusMetaProperty *mpr               = &mif->dbus_properties[l];
            gs_free char *             obj_property_name = NULL;
            const struct {
                const char *dbus_type;
                GType       default_gtype;
            } * p_expected_type, *p_expected_type_2,
                expected_types[] = {
                    {"b", G_TYPE_BOOLEAN},        {"q", G_TYPE_UINT},
                    {"y", G_TYPE_UCHAR},          {"i", G_TYPE_INT},
                    {"u", G_TYPE_UINT},           {"x", G_TYPE_INT64},
                    {"t", G_TYPE_UINT64},         {"s", G_TYPE_STRING},
                    {"o", G_TYPE_STRING},         {"ay", G_TYPE_BYTES},
                    {"as", G_TYPE_STRV},          {"ao", G_TYPE_PTR_ARRAY},
                    {"a{sv}", G_TYPE_HASH_TABLE}, {"aa{sv}", G_TYPE_PTR_ARRAY},

                    {"(uu)", G_TYPE_NONE},        {"aau", G_TYPE_NONE},
                    {"au", G_TYPE_NONE},          {"a(ayuay)", G_TYPE_NONE},
                    {"aay", G_TYPE_NONE},         {"a(ayuayu)", G_TYPE_NONE},

                    {"u", G_TYPE_FLAGS},          {"u", G_TYPE_ENUM},
                    {"o", NM_TYPE_OBJECT},
                };
            const GParamSpec *pspec = NULL;

            g_assert(mpr->dbus_property_name);
            g_assert(g_variant_type_string_is_valid((const char *) mpr->dbus_type));
            if (l > 0) {
                if (strcmp(mif->dbus_properties[l - 1].dbus_property_name, mpr->dbus_property_name)
                    >= 0) {
                    g_error("meta-ifaces[%s] must have property #%u \"%s\" after #%u \"%s\"",
                            mif->dbus_iface_name,
                            l - 1,
                            mif->dbus_properties[l - 1].dbus_property_name,
                            l,
                            mpr->dbus_property_name);
                }
            }

            obj_property_name = nm_utils_wincaps_to_dash(mpr->dbus_property_name);
            g_assert(obj_property_name);

            for (p_expected_type = &expected_types[0]; TRUE;) {
                if (nm_streq((const char *) mpr->dbus_type, p_expected_type->dbus_type))
                    break;
                p_expected_type++;
                if (p_expected_type >= &expected_types[G_N_ELEMENTS(expected_types)]) {
                    g_error("D-Bus type \"%s\" is not implemented (in property %s.%s)",
                            (const char *) mpr->dbus_type,
                            mif->dbus_iface_name,
                            mpr->dbus_property_name);
                }
            }

            if (klass && mpr->obj_properties_idx > 0) {
                g_assert_cmpint(mpr->obj_properties_idx, <, mif->n_obj_properties);
                if (!mpr->obj_property_no_reverse_idx)
                    g_assert_cmpint(mif->obj_properties_reverse_idx[mpr->obj_properties_idx],
                                    ==,
                                    l);
                else {
                    g_assert_cmpint(mif->obj_properties_reverse_idx[mpr->obj_properties_idx],
                                    !=,
                                    l);
                    g_assert_cmpint(mif->obj_properties_reverse_idx[mpr->obj_properties_idx],
                                    !=,
                                    0xFFu);
                }
                pspec = mif->obj_properties[mpr->obj_properties_idx];
            }

            if (mpr->use_notify_update_prop) {
                g_assert(mpr->notify_update_prop);
            } else {
                if (klass)
                    g_assert(pspec);
            }

            if (pspec) {
                const char *expected_property_name;

                if (mif == &_nml_dbus_meta_iface_nm_connection_active
                    && nm_streq(pspec->name, NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT_PATH)) {
                    g_assert_cmpstr(obj_property_name, ==, "specific-object");
                    expected_property_name = NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT_PATH;
                } else if (mif == &_nml_dbus_meta_iface_nm_accesspoint
                           && nm_streq(pspec->name, NM_ACCESS_POINT_BSSID)) {
                    g_assert_cmpstr(obj_property_name, ==, "hw-address");
                    expected_property_name = NM_ACCESS_POINT_BSSID;
                } else if (mif == &_nml_dbus_meta_iface_nm_device_wireguard
                           && nm_streq(pspec->name, NM_DEVICE_WIREGUARD_FWMARK)) {
                    g_assert_cmpstr(obj_property_name, ==, "fw-mark");
                    expected_property_name = NM_DEVICE_WIREGUARD_FWMARK;
                } else if (NM_IN_SET(mif,
                                     &_nml_dbus_meta_iface_nm_ip4config,
                                     &_nml_dbus_meta_iface_nm_ip6config)
                           && nm_streq(pspec->name, NM_IP_CONFIG_ADDRESSES)) {
                    g_assert(NM_IN_STRSET(obj_property_name, "addresses", "address-data"));
                    expected_property_name = NM_IP_CONFIG_ADDRESSES;
                } else if (NM_IN_SET(mif,
                                     &_nml_dbus_meta_iface_nm_ip4config,
                                     &_nml_dbus_meta_iface_nm_ip6config)
                           && nm_streq(pspec->name, NM_IP_CONFIG_ROUTES)) {
                    g_assert(NM_IN_STRSET(obj_property_name, "routes", "route-data"));
                    expected_property_name = NM_IP_CONFIG_ROUTES;
                } else if (NM_IN_SET(mif,
                                     &_nml_dbus_meta_iface_nm_ip4config,
                                     &_nml_dbus_meta_iface_nm_ip6config)
                           && nm_streq(pspec->name, NM_IP_CONFIG_NAMESERVERS)) {
                    g_assert(NM_IN_STRSET(obj_property_name, "nameservers", "nameserver-data"));
                    expected_property_name = NM_IP_CONFIG_NAMESERVERS;
                } else if (mif == &_nml_dbus_meta_iface_nm_ip4config
                           && nm_streq(pspec->name, NM_IP_CONFIG_WINS_SERVERS)) {
                    g_assert(NM_IN_STRSET(obj_property_name, "wins-servers", "wins-server-data"));
                    expected_property_name = NM_IP_CONFIG_WINS_SERVERS;
                } else if (mif == &_nml_dbus_meta_iface_nm_dnsmanager
                           && nm_streq(pspec->name, NM_CLIENT_DNS_CONFIGURATION)) {
                    g_assert_cmpstr(obj_property_name, ==, "configuration");
                    expected_property_name = NM_CLIENT_DNS_CONFIGURATION;
                } else if (mif == &_nml_dbus_meta_iface_nm_dnsmanager
                           && nm_streq(pspec->name, NM_CLIENT_DNS_MODE)) {
                    g_assert_cmpstr(obj_property_name, ==, "mode");
                    expected_property_name = NM_CLIENT_DNS_MODE;
                } else if (mif == &_nml_dbus_meta_iface_nm_dnsmanager
                           && nm_streq(pspec->name, NM_CLIENT_DNS_RC_MANAGER)) {
                    g_assert_cmpstr(obj_property_name, ==, "rc-manager");
                    expected_property_name = NM_CLIENT_DNS_RC_MANAGER;
                } else
                    expected_property_name = obj_property_name;

                g_assert_cmpstr(expected_property_name, ==, pspec->name);

                if (!mpr->use_notify_update_prop) {
                    for (p_expected_type_2 = &expected_types[0];
                         p_expected_type_2 < &expected_types[G_N_ELEMENTS(expected_types)];
                         p_expected_type_2++) {
                        if (!nm_streq((const char *) mpr->dbus_type, p_expected_type_2->dbus_type))
                            continue;
                        if (pspec->value_type == p_expected_type_2->default_gtype
                            || (p_expected_type_2->default_gtype == G_TYPE_ENUM
                                && g_type_is_a(pspec->value_type, G_TYPE_ENUM))
                            || (p_expected_type_2->default_gtype == G_TYPE_FLAGS
                                && g_type_is_a(pspec->value_type, G_TYPE_FLAGS))
                            || (p_expected_type_2->default_gtype == NM_TYPE_OBJECT
                                && nm_streq((const char *) mpr->dbus_type, "o")
                                && g_type_is_a(pspec->value_type, NM_TYPE_OBJECT)))
                            break;
                    }
                    if (p_expected_type_2 >= &expected_types[G_N_ELEMENTS(expected_types)]) {
                        g_error("D-Bus property \"%s.%s\" (type \"%s\") maps to property \"%s\", "
                                "but that has an unexpected property type %s (expected %s)",
                                mif->dbus_iface_name,
                                mpr->dbus_property_name,
                                (const char *) mpr->dbus_type,
                                pspec->name,
                                g_type_name(pspec->value_type),
                                g_type_name(p_expected_type->default_gtype));
                    }
                }

                if (!nm_utils_g_param_spec_is_default(pspec)) {
                    /* We expect our properties to have a default value of zero/NULL.
                     * Except those whitelisted here: */
                    if ((mif == &_nml_dbus_meta_iface_nm_accesspoint
                         && nm_streq(pspec->name, NM_ACCESS_POINT_LAST_SEEN))
                        || (mif == &_nml_dbus_meta_iface_nm_device_vxlan
                            && nm_streq(pspec->name, NM_DEVICE_VXLAN_LEARNING))
                        || (mif == &_nml_dbus_meta_iface_nm_device_wireless
                            && nm_streq(pspec->name, NM_DEVICE_WIFI_LAST_SCAN))
                        || (mif == &_nml_dbus_meta_iface_nm_wifip2ppeer
                            && nm_streq(pspec->name, NM_WIFI_P2P_PEER_LAST_SEEN))
                        || (mif == &_nml_dbus_meta_iface_nm_device_tun
                            && NM_IN_STRSET(pspec->name,
                                            NM_DEVICE_TUN_GROUP,
                                            NM_DEVICE_TUN_OWNER))) {
                        /* pass */
                    } else {
                        g_error("property %s.%s (%s.%s) does not have a default value of zero",
                                mif->dbus_iface_name,
                                mpr->dbus_property_name,
                                g_type_name(gtype),
                                pspec->name);
                    }
                }
            }
        }

        if (klass) {
            for (l = 0; l < mif->n_obj_properties; l++) {
                guint8 ridx = mif->obj_properties_reverse_idx[l];

                if (ridx != 0xFFu)
                    g_assert_cmpint(mif->dbus_properties[ridx].obj_properties_idx, ==, l);
            }
        }

        g_assert(mif == nml_dbus_meta_iface_get(mif->dbus_iface_name));
    }

    meta_iface = nml_dbus_meta_iface_get(NM_DBUS_INTERFACE);
    g_assert(meta_iface);
    g_assert(meta_iface == &_nml_dbus_meta_iface_nm);
    g_assert_cmpstr(meta_iface->dbus_iface_name, ==, NM_DBUS_INTERFACE);

    meta_property = nml_dbus_meta_property_get(meta_iface, "Version", &prop_idx);
    g_assert(meta_property);
    g_assert_cmpstr(meta_property->dbus_property_name, ==, "Version");
    g_assert(&meta_iface->dbus_properties[prop_idx] == meta_property);
}

/*****************************************************************************/

static void
test_dbus_meta_types(void)
{
    struct list_data {
        const char *            dbus_iface_name;
        GType                   gtype;
        NMLDBusMetaInteracePrio interface_prio;
    } list[] = {
        {
            NM_DBUS_INTERFACE,
            NM_TYPE_CLIENT,
            NML_DBUS_META_INTERFACE_PRIO_NMCLIENT,
        },
        {
            NM_DBUS_INTERFACE_ACCESS_POINT,
            NM_TYPE_ACCESS_POINT,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
            NM_TYPE_ACTIVE_CONNECTION,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_10,
        }, /* otherwise, NM_TYPE_VPN_CONNECTION. */
        {
            NM_DBUS_INTERFACE_DEVICE_6LOWPAN,
            NM_TYPE_DEVICE_6LOWPAN,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_ADSL,
            NM_TYPE_DEVICE_ADSL,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_BOND,
            NM_TYPE_DEVICE_BOND,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_BRIDGE,
            NM_TYPE_DEVICE_BRIDGE,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_BLUETOOTH,
            NM_TYPE_DEVICE_BT,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_DUMMY,
            NM_TYPE_DEVICE_DUMMY,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_WIRED,
            NM_TYPE_DEVICE_ETHERNET,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_20,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_VETH,
            NM_TYPE_DEVICE_VETH,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_GENERIC,
            NM_TYPE_DEVICE_GENERIC,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_INFINIBAND,
            NM_TYPE_DEVICE_INFINIBAND,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_IP_TUNNEL,
            NM_TYPE_DEVICE_IP_TUNNEL,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_MACSEC,
            NM_TYPE_DEVICE_MACSEC,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_MACVLAN,
            NM_TYPE_DEVICE_MACVLAN,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_MODEM,
            NM_TYPE_DEVICE_MODEM,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_OLPC_MESH,
            NM_TYPE_DEVICE_OLPC_MESH,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_OVS_INTERFACE,
            NM_TYPE_DEVICE_OVS_INTERFACE,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_OVS_PORT,
            NM_TYPE_DEVICE_OVS_PORT,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_OVS_BRIDGE,
            NM_TYPE_DEVICE_OVS_BRIDGE,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_WIFI_P2P,
            NM_TYPE_DEVICE_WIFI_P2P,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_PPP,
            NM_TYPE_DEVICE_PPP,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_TEAM,
            NM_TYPE_DEVICE_TEAM,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_TUN,
            NM_TYPE_DEVICE_TUN,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_VLAN,
            NM_TYPE_DEVICE_VLAN,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_WPAN,
            NM_TYPE_DEVICE_WPAN,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_VXLAN,
            NM_TYPE_DEVICE_VXLAN,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_WIRELESS,
            NM_TYPE_DEVICE_WIFI,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DEVICE_WIREGUARD,
            NM_TYPE_DEVICE_WIREGUARD,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DHCP4_CONFIG,
            NM_TYPE_DHCP4_CONFIG,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_DHCP6_CONFIG,
            NM_TYPE_DHCP6_CONFIG,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_IP4_CONFIG,
            NM_TYPE_IP4_CONFIG,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_IP6_CONFIG,
            NM_TYPE_IP6_CONFIG,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_WIFI_P2P_PEER,
            NM_TYPE_WIFI_P2P_PEER,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_SETTINGS_CONNECTION,
            NM_TYPE_REMOTE_CONNECTION,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_SETTINGS,
            NM_TYPE_CLIENT,
            NML_DBUS_META_INTERFACE_PRIO_NMCLIENT,
        },
        {
            NM_DBUS_INTERFACE_DNS_MANAGER,
            NM_TYPE_CLIENT,
            NML_DBUS_META_INTERFACE_PRIO_NMCLIENT,
        },
        {
            NM_DBUS_INTERFACE_VPN_CONNECTION,
            NM_TYPE_VPN_CONNECTION,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
        {
            NM_DBUS_INTERFACE_CHECKPOINT,
            NM_TYPE_CHECKPOINT,
            NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
        },
    };
    guint i;

    /* These iface<->gtype associations are copied from "nm-client.c"'s obj_nm_for_gdbus_object().
     * This is redundant to the meta-data, still check that the meta data matches. */
    for (i = 0; i < G_N_ELEMENTS(list); i++) {
        const struct list_data *d = &list[i];
        const NMLDBusMetaIface *meta_iface;

        meta_iface = nml_dbus_meta_iface_get(d->dbus_iface_name);
        g_assert(meta_iface);
        g_assert_cmpint(meta_iface->interface_prio, ==, d->interface_prio);
        g_assert(meta_iface->get_type_fcn() == d->gtype);
    }
}

/*****************************************************************************/

static void
test_nm_auth_permissions(void)
{
    int i, j;

    G_STATIC_ASSERT(G_N_ELEMENTS(nm_auth_permission_names_by_idx) == NM_CLIENT_PERMISSION_LAST);
    G_STATIC_ASSERT(G_N_ELEMENTS(nm_auth_permission_sorted) == NM_CLIENT_PERMISSION_LAST);

    for (i = 0; i < NM_CLIENT_PERMISSION_LAST; i++) {
        g_assert(nm_auth_permission_names_by_idx[i]);
        g_assert(NM_STR_HAS_PREFIX(nm_auth_permission_names_by_idx[i],
                                   "org.freedesktop.NetworkManager."));
        g_assert_cmpint(nm_auth_permission_sorted[i], >, 0);
        g_assert_cmpint(nm_auth_permission_sorted[i], <=, NM_CLIENT_PERMISSION_LAST);
        for (j = i + 1; j < NM_CLIENT_PERMISSION_LAST; j++) {
            g_assert_cmpint(nm_auth_permission_sorted[i], !=, nm_auth_permission_sorted[j]);
            g_assert_cmpstr(nm_auth_permission_names_by_idx[i],
                            !=,
                            nm_auth_permission_names_by_idx[j]);
        }
    }
    for (i = 1; i < NM_CLIENT_PERMISSION_LAST; i++) {
        NMClientPermission a   = nm_auth_permission_sorted[i - 1];
        NMClientPermission b   = nm_auth_permission_sorted[i];
        const char *       s_a = nm_auth_permission_names_by_idx[a - 1];
        const char *       s_b = nm_auth_permission_names_by_idx[b - 1];

        g_assert_cmpstr(s_a, <, s_b);
        g_assert(a != b);
        g_assert(s_a != s_b);
    }
    for (i = 1; i <= NM_CLIENT_PERMISSION_LAST; i++) {
        const char *s = nm_auth_permission_to_string(i);

        g_assert_cmpstr(s, ==, nm_auth_permission_names_by_idx[i - 1]);
        g_assert(s == nm_auth_permission_names_by_idx[i - 1]);
        g_assert_cmpint(nm_auth_permission_from_string(s), ==, i);
    }

    for (i = 0; i < NM_CLIENT_PERMISSION_LAST; i++)
        g_assert_cmpint(nm_auth_permission_from_string(nm_auth_permission_names_by_idx[i]),
                        ==,
                        i + 1);
}

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    g_test_add_func("/libnm/general/fixup_product_string", test_fixup_product_string);
    g_test_add_func("/libnm/general/fixup_vendor_string", test_fixup_vendor_string);
    g_test_add_func("/libnm/general/nm_vpn_service_plugin_read_vpn_details",
                    test_nm_vpn_service_plugin_read_vpn_details);
    g_test_add_func("/libnm/general/test_types", test_types);
    g_test_add_func("/libnm/general/test_nml_dbus_meta", test_nml_dbus_meta);
    g_test_add_func("/libnm/general/test_dbus_meta_types", test_dbus_meta_types);
    g_test_add_func("/libnm/general/test_nm_auth_permissions", test_nm_auth_permissions);

    return g_test_run();
}
