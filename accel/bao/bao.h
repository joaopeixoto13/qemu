// SPDX-License-Identifier: GPL-2.0
/*
 * Bao Header File
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *  
 * Author:
 *	João Peixoto <joaopeixotooficial@gmail.com>
 */

#ifndef __BAO_H
#define __BAO_H

#include "qemu/error-report.h"
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include "sysemu/bao.h"

#define BAO_IO_WRITE 0x0
#define BAO_IO_READ 0x1
#define BAO_IO_ASK 0x2
#define BAO_IO_NOTIFY 0x3

/**
 * @struct bao_virtio_request
 * @brief Bao VirtIO request structure
 */
struct bao_virtio_request {
	uint64_t virtio_id;     /**< VirtIO ID */
	uint64_t addr;          /**< MMIO address */
	uint64_t op;            /**< Operation */
	uint64_t value;         /**< Value */
	uint64_t access_width;  /**< Access width */
    uint64_t cpu_id;        /**< Frontend CPU ID */
    uint64_t vcpu_id;       /**< Frontend VCPU ID */
	int32_t ret;            /**< Return value */
};

/**
 * @struct bao_ioeventfd
 * @brief Bao ioeventfd structure
 */
struct bao_ioeventfd {
	uint32_t fd;            /**< File descriptor */
	uint32_t flags;         /**< Flags (BAO_IOEVENTFD_FLAG_*) */
	uint64_t addr;          /**< MMIO address */
	uint32_t len;           /**< Length */
	uint32_t reserved;      /**< Reserved */
	uint64_t data;          /**< Data (Virtqueue index if datamatch) */
};

/**
 * @struct bao_irqfd
 * @brief Bao irqfd structure
 */
struct bao_irqfd {
	int32_t fd;             /**< File descriptor */
	uint32_t flags;         /**< Flags (BAO_IRQFD_FLAG_*) */
};

/**
 * @struct bao_cmd_params
 * @brief Bao's command line parameters structure
 */
struct bao_cmd_params
{
    int64_t dm_id;          /**< Device Model ID */
    int64_t irq;            /**< QEMU IRQ device number (e.g., qemu-arch64-virt allocates the first device with an IRQ number of 0x2f and goes down from there) */
};

/**
 * @brief Bao ioeventfd flags
 */
#define BAO_IOEVENTFD_FLAG_ASSIGN 0x00
#define BAO_IOEVENTFD_FLAG_DATAMATCH (1 << 1)
#define BAO_IOEVENTFD_FLAG_DEASSIGN (1 << 2)

/**
 * @brief Bao irqfd flags
 */
#define BAO_IRQFD_FLAG_ASSIGN 0x00
#define BAO_IRQFD_FLAG_DEASSIGN	0x01

/**
 * @struct bao_frontend_dm
 * @brief Bao frontend device model structure
 */
struct bao_frontend_dm {
    int fd;                                                                                         /**< Bao file descriptor */
    int dm_fd;                                                                                      /**< DM file descriptor */
    uint64_t dm_id;                                                                                 /**< DM ID (or VirtIO ID) */
    int irq;                                                                                        /**< QEMU device IRQ number */
    uint64_t shmem_addr;                                                                            /**< Shared memory base address */
    uint64_t shmem_size;                                                                            /**< Shared memory size */
    struct bao_virtio_request req;                                                                  /**< VirtIO request */
    int (*get_info)(struct bao_frontend_dm *self);                                                  /**< Get DM info method */
    int (*attach_io_client)(struct bao_frontend_dm *self, struct bao_virtio_request *req);          /**< Attach IO Client method */
    int (*notify_io_completed)(struct bao_frontend_dm *self, struct bao_virtio_request *req);       /**< Notify IO completed method */
    int (*configure_ioeventfd)(struct bao_frontend_dm *self, struct bao_ioeventfd *ioeventfd);      /**< Configure ioeventfd method */
    int (*configure_irqfd)(struct bao_frontend_dm *self, struct bao_irqfd *irqfd);                  /**< Configure irqfd method */
};

/**
 * @brief Get DM info
 * @param self Bao frontend device model
 * @return Returns the DM file descriptor on success, -1 on failure
 */
int bao_dm_get_info(struct bao_frontend_dm *self);

/**
 * @brief Attach I/O client (control client)
 * @param self Bao frontend device model
 * @param req VirtIO request that will be updated when the thread receives a response
 * @return Returns 0 on success, -1 on failure
 */
int bao_attach_io_client(struct bao_frontend_dm *self, struct bao_virtio_request *req);

/**
 * @brief Notify I/O completed
 * @param self Bao frontend device model
 * @param req VirtIO request to update
 * @return Returns 0 on success, -1 on failure
 */
int bao_notify_io_completed(struct bao_frontend_dm *self, struct bao_virtio_request *req);

/**
 * @brief Create ioeventfd
 * @param self Bao frontend device model
 * @param ioeventfd ioeventfd structure to configure
 * @return Returns 0 on success, -1 on failure
 */
int bao_create_ioeventfd(struct bao_frontend_dm *self, struct bao_ioeventfd *ioeventfd);

/**
 * @brief Create irqfd
 * @param self Bao frontend device model
 * @param irqfd irqfd structure to configure
 * @return Returns 0 on success, -1 on failure
 */
int bao_create_irqfd(struct bao_frontend_dm *self, struct bao_irqfd *irqfd);

/**
 * @brief Create Bao frontend device model
 * @param params Bao command line parameters
 * @return Returns the Bao frontend device model
 */
struct bao_frontend_dm bao_create_dm(struct bao_cmd_params params);

#endif // __BAO_IOREQ_API_H