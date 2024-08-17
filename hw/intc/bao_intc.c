/*
 * Bao Hypervisor Interrupt Controller (INTC) for QEMU
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
#include "qemu/module.h"
#include "qom/object.h"
#include "hw/sysbus.h"
#include "qemu/log.h"
#include "hw/qdev-properties.h"
#include "gic_internal.h"
#include "sysemu/bao.h"

#define TYPE_BAO_INTC "bao-intc"
OBJECT_DECLARE_SIMPLE_TYPE(BaoIntcState, BAO_INTC)

/**
 * @struct BaoIntcState
 * @brief Bao Interrupt Controller (INTC) state
 */
struct BaoIntcState {
    SysBusDevice parent_obj;    /**< Parent object */
    uint32_t num_irqs;          /**< Number of IRQs */
};
typedef struct BaoIntcState BaoIntcState;

/**
 * @brief Bao interrupt controller set method
 * @param opaque Pointer to the Bao INTC state
 * @param irq The IRQ number
 * @param level The IRQ level
 */
static void bao_intc_set_irq(void *opaque, int irq, int level)
{
    BaoIntcState *s = opaque;

    if (irq < s->num_irqs)
        bao_set_irq(irq, level);
}

/**
 * @brief Bao interrupt controller realize method
 * @param dev Device state
 * @param errp Error pointer
 */
static void bao_intc_realize(DeviceState *dev, Error **errp)
{
    BaoIntcState *s = BAO_INTC(dev);

    if (s->num_irqs > GIC_MAXIRQ) {
        error_setg(errp,
                   "requested %u interrupt lines exceeds GIC maximum %d",
                   s->num_irqs, GIC_MAXIRQ);
        return;
    }

    qdev_init_gpio_in(dev, bao_intc_set_irq, s->num_irqs);
}

static Property bao_intc_properties[] = {
    DEFINE_PROP_UINT32("num-irqs", BaoIntcState, num_irqs, BAO_DM_NUM_MAX),
    DEFINE_PROP_END_OF_LIST(),
};

/**
 * @brief Bao interrupt controller class init method
 * @param klass Object class
 * @param data Pointer to the data
 */
static void bao_intc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_props(dc, bao_intc_properties);

    dc->realize = bao_intc_realize;
}

static const TypeInfo bao_intc_info = {
    .name = TYPE_BAO_INTC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(BaoIntcState),
    .class_init = bao_intc_class_init,
};

/**
 * @brief Register the Bao INTC types
 */
static void bao_intc_register_types(void)
{
    type_register_static(&bao_intc_info);
}

type_init(bao_intc_register_types)
