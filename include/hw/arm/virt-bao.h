/*
 * Bao Hypervisor Machine Memory Map
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 * Authors:
 *  João Peixoto   <joaopeixotooficial@gmail.com>
 */

#ifndef QEMU_ARM_BAO_VIRT_H
#define QEMU_ARM_BAO_VIRT_H

#include "hw/arm/virt.h"

/**
 * @brief Initialize the memory map for the Bao Hypervisor
 * @param vms The virtual machine state
 */
void bao_virt_memmap_init(VirtMachineState *vms);

/**
 * @brief Sets the memory map for the Bao Hypervisor
 * @param base The base address of the memory map
 * @param size The size of the memory map
 */
void bao_virt_memmap_set(hwaddr base, hwaddr size);

#endif