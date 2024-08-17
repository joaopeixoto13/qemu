/*
 * QEMU Bao support
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 * Authors:
 *  João Peixoto   <joaopeixotooficial@gmail.com>
 */

#ifndef BAO_H
#define BAO_H

#ifdef NEED_CPU_H
#ifdef CONFIG_BAO
#define CONFIG_BAO_IS_POSSIBLE
#endif
#else
#define CONFIG_BAO_IS_POSSIBLE
#endif

#ifdef CONFIG_BAO_IS_POSSIBLE

extern bool bao_allowed;

#define bao_enabled() (bao_allowed)
#define bao_eventfds_enabled() (true)

#define BAO_DM_NUM_MAX 16

/**
 * @brief Set the IRQ flag
 * @param irq QEMU device IRQ number
 * @param value Value to set the IRQ flag
 */
void bao_set_irq(int irq, bool value);

#else /* !CONFIG_BAO_IS_POSSIBLE */

#define bao_enabled() (false)
#define bao_eventfds_enabled() (false)

#endif /* CONFIG_BAO_IS_POSSIBLE */

#endif /* BAO_H */