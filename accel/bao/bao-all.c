// SPDX-License-Identifier: GPL-2.0
/*
 * Bao Source File
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Author:
 *	João Peixoto <joaopeixotooficial@gmail.com>
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qemu/accel.h"
#include "qemu/atomic.h"
#include "sysemu/cpus.h"
#include "sysemu/runstate.h"
#include "sysemu/bao.h"
#include "hw/boards.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "migration/vmstate.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qemu/qemu-options.h"
#include "hw/arm/virt.h"
#include "hw/arm/virt-bao.h"
#include <stdarg.h>
#include <sys/ioctl.h>
#include "bao.h"
#include "qemu/event_notifier.h"

/**
 * qemu-aarch64-virt first device IRQ number
 * The subsequent IRQ numbers are assigned to the devices
 */
#define BAO_QEMU_AARCH64_VIRT_FIRST_DEV_IRQ 0x2f

/**< IRQ offset calculator for the IRQ array  for qemu-aarch64-virt */
#define IRQ_OFFSET (BAO_QEMU_AARCH64_VIRT_FIRST_DEV_IRQ - BAO_DM_NUM_MAX + 1)

/**< Calculate the IRQ index */
#define CALCULATE_IRQ_IDX(irq) (irq - IRQ_OFFSET)

/**< Bao allowed flag */
bool bao_allowed;

/**< QEMU thread to handle the control path */
static QemuThread control_plane_thread;

/**< QEMU thread to handle the data path */
static QemuThread data_plane_thread;

/**
 * @brief Control plane worker thread
 * @param opaque Pointer to the BaoDM structure
 * @return NULL 
 */
static void *control_plane_worker_thread(void *opaque);

/**
 * @brief Data plane worker thread
 * @param opaque Pointer to the BaoDM structure
 * @return NULL 
 */
static void *data_plane_worker_thread(void *opaque);

/**
 * @struct BaoDM
 * @brief Bao device model structure
 */
typedef struct BaoDM
{
    struct bao_frontend_dm dm;      /**< Frontend DM */
    MemoryListener mem_listener;    /**< Memory listener (used for I/O eventfd) */
    EventNotifier irqfd;            /**< Event notifier (used for IRQ eventfd) */
} BaoDM;

/**
 * @struct BaoState
 * @brief Bao state structure
 */
typedef struct BaoState
{
    AccelState parent_obj;                  /**< Parent object */
    int dm_num;                             /**< Number of DMs */
    struct BaoDM dm[BAO_DM_NUM_MAX];        /**< DM array */
} BaoState;

/**< Name of the Bao accelerator */
#define TYPE_BAO_ACCEL ACCEL_CLASS_NAME("bao")

/**< BaoState instance checker */
DECLARE_INSTANCE_CHECKER(BaoState, BAO_STATE, TYPE_BAO_ACCEL)

/**
 * IRQ pending array used to check atomically if an IRQ is pending
 * for a specific QEMU device.
 * This is necessary beacuse QEMU's devices inject IRQs into the interrupt
 * controller (bao_intc) which in turn sets the IRQ pending flag.
 * The same applies to vhost and vhost-user devices, since QEMU mantains a loop
 * to check the irqfd file descriptor to check if an IRQ is pending and if so,
 * it injects the IRQ into the interrupt controller.
 */
static volatile int irq_pending[BAO_DM_NUM_MAX] = {0};

/**< Device IRQ array used to store the IRQ number for each QEMU device */
static int device_irq[BAO_DM_NUM_MAX] = {0};

/**< Bao command parameters */
struct bao_cmd_params bao_cmd_params[BAO_DM_NUM_MAX];

int bao_dm_get_info(struct bao_frontend_dm *self)
{
    struct bao_dm_info info;
    int ret;
    info.dm_id = self->dm_id;
    info.shmem_addr = 0;
    info.shmem_size = 0;
    info.irq = 0;
    info.fd = 0;

    if (self->fd < 0)
        return -1;

    ret = ioctl(self->fd, BAO_IOCTL_IO_DM_GET_INFO, &info);

    if (ret < 0)
        return -1;

    self->dm_fd = info.fd;
    self->shmem_addr = info.shmem_addr;
    self->shmem_size = info.shmem_size;
    return self->dm_fd;
}

int bao_attach_io_client(struct bao_frontend_dm *self, struct bao_virtio_request *req)
{
    return ioctl(self->dm_fd, BAO_IOCTL_IO_CLIENT_ATTACH, req);
}

int bao_notify_io_completed(struct bao_frontend_dm *self, struct bao_virtio_request *req)
{
    return ioctl(self->dm_fd, BAO_IOCTL_IO_REQUEST_COMPLETE, req);
}

int bao_create_ioeventfd(struct bao_frontend_dm *self, struct bao_ioeventfd *ioeventfd)
{
    return ioctl(self->dm_fd, BAO_IOCTL_IOEVENTFD, ioeventfd);
}

int bao_create_irqfd(struct bao_frontend_dm *self, struct bao_irqfd *irqfd)
{
    return ioctl(self->dm_fd, BAO_IOCTL_IRQFD, irqfd);
}

struct bao_frontend_dm bao_create_dm(struct bao_cmd_params params)
{
    struct bao_frontend_dm vm;
    vm.fd = open("/dev/bao-io-dispatcher", O_RDWR);
    vm.dm_id = params.dm_id;
    vm.dm_fd = -1;
    vm.irq = params.irq;
    vm.shmem_addr = 0;
    vm.shmem_size = 0;
    vm.get_info = bao_dm_get_info;
    vm.attach_io_client = bao_attach_io_client;
    vm.notify_io_completed = bao_notify_io_completed;
    vm.configure_ioeventfd = bao_create_ioeventfd;
    vm.configure_irqfd = bao_create_irqfd;
    if (vm.get_info(&vm) < 0) {
        error_report("Failed to get DM info");
        exit(1);
    }
    return vm;
}

void bao_set_irq(int irq, bool value)
{
    /**< Update the IRQ number index */
    int irq_idx = CALCULATE_IRQ_IDX(irq);

    /**< Check if the IRQ number is the same as the device IRQ */
    if (device_irq[irq_idx] == irq)
        qatomic_set(&irq_pending[irq_idx], value);
}

/**
 * @brief Check if the IRQ flag is set
 * @param irq QEMU device IRQ number to check
 * @return Returns true if the IRQ flag is set, false otherwise
 */
static bool bao_irq_is_pending(int irq)
{
    /**< Update the IRQ number index */
    int irq_idx = CALCULATE_IRQ_IDX(irq);

    return qatomic_read(&irq_pending[irq_idx]);
}

/**
 * @brief Configure a I/O eventfd
 * @param s BaoDM
 * @param fd File descriptor to configure
 * @param addr Address to configure (for MMIO devices the address offset is 0x50)
 * @param data Virqueue index if datamatch is set
 * @param assign Assign or deassign the ioevendfd
 * @param size Size of the region to configure (generally 4 bytes)
 * @param datamatch Data to match (support for one ioevendfd per virtqueue)
 * @return Returns 0 on success, <0 on failure
 */
static int bao_ioeventfd_set(BaoDM *s, int fd, hwaddr addr, uint32_t data,
                             bool assign, uint32_t size, bool datamatch)
{
    struct bao_ioeventfd config = {
        .fd = fd,
        .addr = addr,
        .len = size,
        .data = datamatch ? data : 0,
        .flags = BAO_IOEVENTFD_FLAG_ASSIGN,
    };

    if (datamatch)
    {
        config.flags |= BAO_IOEVENTFD_FLAG_DATAMATCH;
    }

    if (!assign)
    {
        config.flags |= BAO_IOEVENTFD_FLAG_DEASSIGN;
    }

    return s->dm.configure_ioeventfd(&s->dm, &config);
}

/**
 * @brief Configure a IRQ eventfd
 * @param s BaoDM
 * @param fd File descriptor to configure
 * @param assign Assign or deassign the irqfd
 * @return Returns 0 on success, <0 on failure
 */
static int bao_irqfd_set(BaoDM *s, int fd, bool assign)
{
    struct bao_irqfd config = {
        .fd = fd,
        .flags = BAO_IRQFD_FLAG_ASSIGN,
    };

    if (!assign)
    {
        config.flags |= BAO_IRQFD_FLAG_DEASSIGN;
    }

    return s->dm.configure_irqfd(&s->dm, &config);
}

/**
 * @brief Setup the Bao worker threads
 * @note Invoked after the machine is setup
 * @param ms MachineState
 * @param accel AccelState
 */
static void bao_setup_post(MachineState *ms, AccelState *accel)
{
    BaoState *s = BAO_STATE(ms->accelerator);
    char name[32];

    for (int i = 0; i < s->dm_num; i++)
    {
        snprintf(name, sizeof(name), "crt-pln-dm-%d", i);

        /**< Create the QEMU thread to handle the control path */
        qemu_thread_create(&control_plane_thread, name,
                       control_plane_worker_thread, &s->dm[i], QEMU_THREAD_JOINABLE);

        snprintf(name, sizeof(name), "dat-pln-dm-%d", i);

        /**< Create the QEMU thread to handle the data path */
        qemu_thread_create(&data_plane_thread, name,
                        data_plane_worker_thread, &s->dm[i], QEMU_THREAD_JOINABLE);
    }
}

/**
 * @brief Handle the I/O request
 * @param s BaoDM
 */
static inline void handle_io_req(BaoDM *s)
{
    MemTxResult ret = MEMTX_OK;

    qemu_mutex_lock_iothread();

    switch (s->dm.req.op)
    {
    case BAO_IO_WRITE:
        ret = address_space_write(&address_space_memory, s->dm.req.addr, MEMTXATTRS_UNSPECIFIED, &s->dm.req.value, s->dm.req.access_width);
        break;
    case BAO_IO_READ:
        ret = address_space_read(&address_space_memory, s->dm.req.addr, MEMTXATTRS_UNSPECIFIED, &s->dm.req.value, s->dm.req.access_width);
        break;
    case BAO_IO_ASK:
    case BAO_IO_NOTIFY:
        break;
    default:
        error_report("invalid ioreq direction (%d)", (int)s->dm.req.op);
        break;
    }

    qemu_mutex_unlock_iothread();

    if (ret != MEMTX_OK)
    {
        error_report("failed to %s memory at 0x%lx",
                     s->dm.req.op == BAO_IO_WRITE ? "write" : "read",
                     (unsigned long)s->dm.req.addr);
    }
}

static void *control_plane_worker_thread(void *opaque)
{
    BaoDM *s = opaque;
    int rc = 0;

    for (;;)
    {
        s->dm.req.virtio_id = 0x0;
        s->dm.req.addr = 0x0;
        s->dm.req.op = BAO_IO_ASK;
        s->dm.req.value = 0x0;
        s->dm.req.access_width = 0x0;
        s->dm.req.request_id = 0x0;
        s->dm.req.ret = 0x0;

        /**< Attach the control client */
        rc = s->dm.attach_io_client(&s->dm, &s->dm.req);
        if (rc < 0)
            return NULL;

        /**< Handle the I/O request */
        handle_io_req(s);

        /**< Notify I/O completed */
        rc = s->dm.notify_io_completed(&s->dm, &s->dm.req);
        if (rc < 0)
            return NULL;
    }

    return NULL;
}

static void *data_plane_worker_thread(void *opaque)
{
    BaoDM *s = opaque;

    /**< Create a file descriptor for the irqfd */
    int rc = event_notifier_init(&s->irqfd, false);
    if (rc < 0)
        return NULL;

    /**< Extract the file descriptor */
    int fd = event_notifier_get_fd(&s->irqfd);

    /**< Configure the irqfd */
    rc = bao_irqfd_set(s, fd, true);
    if (rc < 0)
        return NULL;

    for (;;)
    {
        /**< Check for pending IRQs */
        if (bao_irq_is_pending(s->dm.irq))
        {
            qemu_mutex_lock_iothread();

            /**< Inject an irqfd */
            rc = event_notifier_set(&s->irqfd);

            /**< Clear the IRQ flag */
            bao_set_irq(s->dm.irq, false);

            qemu_mutex_unlock_iothread();
        }
    }

    return NULL;
}

/**
 * @brief Add a I/O eventfd
 * @param listener MemoryListener (contains the event to listen)
 * @param section MemoryRegionSection (contains the offset and size associated with the event to listen)
 * @param datamatch Data to match (support for one ioevendfd per virtqueue)
 * @param data Virqueue index if datamatch is set
 * @param e EventNotifier (contains the ioeventfd)
 */
static void bao_io_ioeventfd_add(MemoryListener *listener,
                                 MemoryRegionSection *section,
                                 bool datamatch, uint64_t data,
                                 EventNotifier *e)
{
    BaoDM *s = container_of(listener, BaoDM, mem_listener);
    int fd = event_notifier_get_fd(e);
    int rc;

    rc = bao_ioeventfd_set(s, fd, section->offset_within_address_space,
                           data, true, int128_get64(section->size),
                           datamatch);
    if (rc < 0)
    {
        error_report("Adding ioeventfd: %s\n", strerror(-rc));
        exit(1);
    }
}

/**
 * @brief Delete a I/O eventfd
 * @param listener MemoryListener (contains the event to listen)
 * @param section MemoryRegionSection (contains the offset and size associated with the event to listen)
 * @param datamatch Data to match (support for one ioevendfd per virtqueue)
 * @param data Virqueue index if datamatch is set
 * @param e EventNotifier (contains the ioeventfd)
 */
static void bao_io_ioeventfd_del(MemoryListener *listener,
                                 MemoryRegionSection *section,
                                 bool datamatch, uint64_t data,
                                 EventNotifier *e)

{
    BaoDM *s = container_of(listener, BaoDM, mem_listener);
    int fd = event_notifier_get_fd(e);
    int rc;

    rc = bao_ioeventfd_set(s, fd, section->offset_within_address_space,
                           data, false, int128_get64(section->size),
                           datamatch);
    if (rc < 0)
    {
        error_report("Deleting ioeventfd: %s\n", strerror(-rc));
        exit(1);
    }
}

/**
 * @brief Add a region
 * @param listener MemoryListener
 * @param section MemoryRegionSection
 */
static void bao_region_add(MemoryListener *listener, MemoryRegionSection *section)
{
}

/**
 * @brief Delete a region
 * @param listener MemoryListener
 * @param section MemoryRegionSection
 */
static void bao_region_del(MemoryListener *listener, MemoryRegionSection *section)
{
}

/**
 * @brief Change the state handler
 * @param opaque BaoState
 * @param running Specifies whether the DM is running or not
 * @param state RunState
 */
static void bao_change_state_handler(void *opaque, bool running, RunState state)
{
    if (running) 
    {
        info_report("Starting QEMU app...\n");
    }
}

/**
 * @brief Tokenize a string
 * @param optarg String to tokenize
 * @param delim Delimiter
 * @param tokens Array to store the tokens
 * @param max_tokens Maximum number of tokens to tokenize
 * @return Returns the number of tokens
 */
static int bao_tokenizer(const char *optarg, const char *delim, int tokens[], int max_tokens)
{
    char *token;
    int i = 0;

    char *optarg_cpy = strdup(optarg);

    token = strtok(optarg_cpy, delim);
    while (token != NULL && i < max_tokens)
    {
        tokens[i++] = strtoull(token, NULL, 10);
        token = strtok(NULL, delim);
    }

    free(optarg_cpy);

    return i;
}

/**
 * @brief Parse the command line arguments
 * @return Returns the number of DMs
 */
static int bao_parse_cmdline(void)
{
    int dms[BAO_DM_NUM_MAX];
    int irqs[BAO_DM_NUM_MAX];

    const char *vms_str = qemu_opt_get(qemu_find_opts_singleton("bao"), "dm_id");
    const char *irqs_str = qemu_opt_get(qemu_find_opts_singleton("bao"), "irq");

    if (vms_str == NULL || irqs_str == NULL)
    {
        error_report("Failed to parse command line arguments.\n");
        exit(1);
    }

    int num_dms = bao_tokenizer(vms_str, "-", dms, BAO_DM_NUM_MAX);
    int num_irqs = bao_tokenizer(irqs_str, "-", irqs, BAO_DM_NUM_MAX);

    /**< Check if the number of DMs and IRQs are the same since each DM holds/configures one and only one device */
    if (num_dms != num_irqs)
    {
        error_report("The number of DMs and IRQs must be the same.\n");
        exit(1);
    }

    /**< Update the bao_cmd_params array */
    for (int i = 0; i < num_dms; i++)
    {
        bao_cmd_params[i].dm_id = dms[i];
        bao_cmd_params[i].irq = irqs[i];
    }

    return num_dms;
}

/**
 * @brief Bao accelerator initialization routine
 * @param ms specifies the MachineState
 * @return Always returns 0, otherwise the QEMU will exit
 */
static int bao_init(MachineState *ms)
{
    BaoState *s = BAO_STATE(ms->accelerator);
    uint64_t shmem_addr = 0;
    uint64_t shmem_size = 0;

    for (volatile int i = 0; i < BAO_DM_NUM_MAX; i++)
    {
        bao_cmd_params[i].dm_id = 0;
        bao_cmd_params[i].irq = 0;
    }

    /**< Parse the command line arguments */
    s->dm_num = bao_parse_cmdline();
    if (!s->dm_num)
    {
        error_report("Failed to parse command line arguments.\n");
        exit(1);
    }

    for (volatile int i = 0; i < s->dm_num; i++)
    {
        /**< Create the DM */
        s->dm[i].dm = bao_create_dm(bao_cmd_params[i]);

        /**< Update the shared memory size */
        shmem_size += s->dm[i].dm.shmem_size;
    }

    /*
    * Set the shared memory base address as the first shared memory address
    * Note: If QEMU is running more than one device, the shared memory address
    * must be contiguous
    */
    shmem_addr = s->dm[0].dm.shmem_addr;

    /**< Set QEMU virtual memory map */
    bao_virt_memmap_set(shmem_addr, shmem_size);

    for (volatile int i = 0; i < s->dm_num; i++)
    {
        /**< Update the device IRQ */
        device_irq[CALCULATE_IRQ_IDX(bao_cmd_params[i].irq)] = bao_cmd_params[i].irq;

        /**< Setup the memory listeners */
        s->dm[i].mem_listener.eventfd_add = bao_io_ioeventfd_add;
        s->dm[i].mem_listener.eventfd_del = bao_io_ioeventfd_del;
        s->dm[i].mem_listener.region_add = bao_region_add;
        s->dm[i].mem_listener.region_del = bao_region_del;
        memory_listener_register(&s->dm[i].mem_listener, &address_space_memory);
    }

    qemu_add_vm_change_state_handler(bao_change_state_handler, s);

    return 0;
}

/**
 * @brief Bao accelerator class initialization routine
 * @param oc ObjectClass
 * @param data specifies the data
 */
static void bao_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);

    ac->name = "bao";
    ac->init_machine = bao_init;
    ac->setup_post = bao_setup_post;
    ac->allowed = &bao_allowed;
}

/**
 * @brief Bao accelerator instance initialization routine
 * @param obj Object
 */
static void bao_accel_instance_init(Object *obj)
{
}

/**< Bao accelerator type */
static const TypeInfo bao_accel_type = {
    .name = TYPE_BAO_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_init = bao_accel_instance_init,
    .class_init = bao_accel_class_init,
    .instance_size = sizeof(BaoState),
};

/**
 * @brief Bao accelerator operations class initialization routine
 * @param oc ObjectClass
 * @param ObjectClass data
 */
static void bao_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);
    ops->create_vcpu_thread = dummy_start_vcpu_thread;
}

/**< Bao accelerator operations type */
static const TypeInfo bao_accel_ops_type = {
    .name = ACCEL_OPS_NAME("bao"),
    .parent = TYPE_ACCEL_OPS,
    .class_init = bao_accel_ops_class_init,
    .abstract = true,
};

/**
 * @brief Bao type initialization routine
 */
static void bao_type_init(void)
{
    type_register_static(&bao_accel_type);
    type_register_static(&bao_accel_ops_type);
}
type_init(bao_type_init);