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

#include <sys/ioctl.h>
#include <stdint.h>

/**
 * @struct bao_dm_info
 * @brief Bao device model info structure
 */
struct bao_dm_info
{
    int32_t dm_id;          /**< Device Model ID */
    uint64_t shmem_addr;    /**< Shared memory base address */
    uint64_t shmem_size;    /**< Shared memory size */
    uint32_t irq;           /**< Device model IRQ number */
    int32_t fd;             /**< Device model file descriptor */
};

/**
 * @brief Bao IOCTLs
 */
#define BAO_IOCTL_TYPE 0xA6
#define BAO_IOCTL_IO_DM_GET_INFO _IOWR(BAO_IOCTL_TYPE, 0x01, struct bao_dm_info)
#define BAO_IOCTL_IO_CLIENT_ATTACH _IOWR(BAO_IOCTL_TYPE, 0x02, struct bao_virtio_request)
#define BAO_IOCTL_IO_REQUEST_COMPLETE \
	_IOW(BAO_IOCTL_TYPE, 0x03, struct bao_virtio_request)
#define BAO_IOCTL_IOEVENTFD _IOW(BAO_IOCTL_TYPE, 0x04, struct bao_ioeventfd)
#define BAO_IOCTL_IRQFD _IOW(BAO_IOCTL_TYPE, 0x05, struct bao_irqfd)

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