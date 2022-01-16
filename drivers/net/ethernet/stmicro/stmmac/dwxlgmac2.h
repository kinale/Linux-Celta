/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 Synopsys, Inc. and/or its affiliates.
 * Synopsys DesignWare XLGMAC definitions.
 */

#ifndef __STMMAC_DWXLGMAC2_H__
#define __STMMAC_DWXLGMAC2_H__

/* MAC Registers */
#define XLGMAC_CONFIG_SS		GENMASK(30, 28)
#define XLGMAC_CONFIG_SS_SHIFT		28
#define XLGMAC_CONFIG_SS_40G		(0x0 << XLGMAC_CONFIG_SS_SHIFT)
#define XLGMAC_CONFIG_SS_25G		(0x1 << XLGMAC_CONFIG_SS_SHIFT)
#define XLGMAC_CONFIG_SS_50G		(0x2 << XLGMAC_CONFIG_SS_SHIFT)
#define XLGMAC_CONFIG_SS_100G		(0x3 << XLGMAC_CONFIG_SS_SHIFT)
#define XLGMAC_CONFIG_SS_10G		(0x4 << XLGMAC_CONFIG_SS_SHIFT)
#define XLGMAC_CONFIG_SS_2500		(0x6 << XLGMAC_CONFIG_SS_SHIFT)
#define XLGMAC_CONFIG_SS_1000		(0x7 << XLGMAC_CONFIG_SS_SHIFT)
#define XLGMAC_RXQ_ENABLE_CTRL0		0x00000140

#endif /* __STMMAC_DWXLGMAC2_H__ */
