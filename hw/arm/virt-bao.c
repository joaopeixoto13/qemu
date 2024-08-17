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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "hw/sysbus.h"
#include "sysemu/bao.h"
#include "hw/arm/virt-bao.h"
#include "hw/pci/pcie_host.h"
#include "hw/pci/pci.h"
#include "net/net.h"

/**< Bao memory map struct */
static MemMapEntry bao_memmap = {0, 0};

void bao_virt_memmap_set(hwaddr base, hwaddr size)
{
    bao_memmap.base = base;
    bao_memmap.size = size;
}

void bao_virt_memmap_init(VirtMachineState *vms)
{
    /**< Check if the machine has a memory map field */
    if (!vms->memmap) {
        fprintf(stderr, "No memmap set for machine\n");
        exit(1);
    }
    /**< Check if the memory map is valid */
    if (bao_memmap.size == 0) {
        fprintf(stderr, "Invalid Bao memory map\n");
        exit(1);
    }

    /**
     * Check if the memory map base address is >= 1GB
     * This is a requirement since qemu-arch64-virt starts the 
     * virtual memory at 1GB
     * (see base_memmap[VIRT_MEM] >= GiB on /hw/arm/virt.c)
     */
    if (bao_memmap.base < 0x40000000) {
        fprintf(stderr, "Bao memory map base address must be >= 1GB\n");
        exit(1);
    }

    /**< Update the memory map */
    vms->memmap[VIRT_MEM] = bao_memmap;
}