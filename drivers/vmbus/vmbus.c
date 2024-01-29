/*-
 * Copyright (c) 2009-2012,2016-2017 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * VM Bus Driver Implementation
 */

#include <inttypes.h>
#include <uk/alloc.h>
#include <uk/arch/types.h>
#include <uk/bus.h>
#include <uk/config.h>
#include <uk/errptr.h>
#include <uk/list.h>
#include <uk/plat/io.h>
#include <uk/print.h>
#include <uk/thread.h>

#include <include/hyperv.h>
#include <include/vmbus.h>
#include <include/vmbus_xact.h>
#include <vmbus_ids.h>
#include <vmbus_config.h>
#include <vmbus/hyperv_var.h>
#include <vmbus/vmbus_chanvar.h>
#include <vmbus/vmbus_reg.h>
#include <vmbus/vmbus_var.h>

#include <hyperv/bsd_layer.h>

#include <hyperv/intctrl.h>

// #include <dev/hyperv/include/hyperv.h>
// #include <dev/hyperv/include/vmbus_xact.h>
// #include <dev/hyperv/vmbus/hyperv_reg.h>
// #include <dev/hyperv/vmbus/hyperv_var.h>
// #include <dev/hyperv/vmbus/vmbus_reg.h>
// #include <dev/hyperv/vmbus/vmbus_var.h>
// #include <dev/hyperv/vmbus/vmbus_chanvar.h>

// #include "acpi_if.h"
// #include "pcib_if.h"
// #include "vmbus_if.h"

extern char hyperv_message_page[PAGE_SIZE];
extern char hyperv_event_flags_page[PAGE_SIZE];

static struct vmbus_handler vbh;

#define VMBUS_GPADL_START		0xe1e10

struct vmbus_msghc {
	struct vmbus_xact		*mh_xact;
	struct hypercall_postmsg_in	mh_inprm_save;
};

// static void			vmbus_identify(driver_t *, device_t);
// static int			vmbus_probe(device_t);
// static int			vmbus_attach(device_t);
static int			vmbus_attach(struct uk_alloc *);
// static int			vmbus_detach(device_t);
// static int			vmbus_read_ivar(device_t, device_t, int,
// 				    uintptr_t *);
// static int			vmbus_child_pnpinfo(device_t, device_t, struct sbuf *);
// static struct resource		*vmbus_alloc_resource(device_t dev,
// 				    device_t child, int type, int *rid,
// 				    rman_res_t start, rman_res_t end,
// 				    rman_res_t count, u_int flags);
// static int			vmbus_alloc_msi(device_t bus, device_t dev,
// 				    int count, int maxcount, int *irqs);
// static int			vmbus_release_msi(device_t bus, device_t dev,
// 				    int count, int *irqs);
// static int			vmbus_alloc_msix(device_t bus, device_t dev,
// 				    int *irq);
// static int			vmbus_release_msix(device_t bus, device_t dev,
// 				    int irq);
// static int			vmbus_map_msi(device_t bus, device_t dev,
// 				    int irq, uint64_t *addr, uint32_t *data);
// static uint32_t			vmbus_get_version_method(device_t, device_t);
// static int			vmbus_probe_guid_method(device_t, device_t,
// 				    const struct hyperv_guid *);
// static uint32_t			vmbus_get_vcpu_id_method(device_t bus,
// 				    device_t dev, int cpu);
// static struct taskqueue		*vmbus_get_eventtq_method(device_t, device_t,
// 				    int);
// #ifdef EARLY_AP_STARTUP
// static void			vmbus_intrhook(void *);
// #endif

static int			vmbus_init(struct vmbus_softc *);
static int			vmbus_connect(struct vmbus_softc *, uint32_t);
static int			vmbus_req_channels(struct vmbus_softc *sc);
// static void			vmbus_disconnect(struct vmbus_softc *);
static int			vmbus_scan(struct vmbus_softc *);
// static void			vmbus_scan_teardown(struct vmbus_softc *);
static void			vmbus_scan_done(struct vmbus_softc *,
				    const struct vmbus_message *);
static void			vmbus_chanmsg_handle(struct vmbus_softc *,
				    const struct vmbus_message *);
void			vmbus_msg_task(void *);
static void			vmbus_synic_setup(void *);
// static void			vmbus_synic_teardown(void *);
// static int			vmbus_sysctl_version(SYSCTL_HANDLER_ARGS);
static int			vmbus_page_alloc(struct vmbus_softc *);
// static void			vmbus_page_free(struct vmbus_softc *);
static int			vmbus_intr_setup(struct vmbus_softc *);
// static void			vmbus_intr_teardown(struct vmbus_softc *);
static int			vmbus_doattach(struct vmbus_softc *);
static void			vmbus_event_proc_dummy(struct vmbus_softc *,
				    int);

static struct vmbus_softc	*vmbus_sc;

static int vmbus_probe_device_type(struct vmbus_channel *chan);

// SYSCTL_NODE(_hw, OID_AUTO, vmbus, CTLFLAG_RD | CTLFLAG_MPSAFE, NULL,
//     "Hyper-V vmbus");

// static int			vmbus_pin_evttask = 1;
// SYSCTL_INT(_hw_vmbus, OID_AUTO, pin_evttask, CTLFLAG_RDTUN,
//     &vmbus_pin_evttask, 0, "Pin event tasks to their respective CPU");

// extern inthand_t IDTVEC(vmbus_isr), IDTVEC(vmbus_isr_pti);
// #define VMBUS_ISR_ADDR	trunc_page((uintptr_t)IDTVEC(vmbus_isr_pti))

uint32_t			vmbus_current_version;

static const uint32_t		vmbus_version[] = {
	VMBUS_VERSION_WIN10,
	VMBUS_VERSION_WIN8_1,
	VMBUS_VERSION_WIN8,
	VMBUS_VERSION_WIN7,
	VMBUS_VERSION_WS2008
};

static const vmbus_chanmsg_proc_t
vmbus_chanmsg_handlers[VMBUS_CHANMSG_TYPE_MAX] = {
	VMBUS_CHANMSG_PROC(CHOFFER_DONE, vmbus_scan_done),
	VMBUS_CHANMSG_PROC_WAKEUP(CONNECT_RESP)
};

// static device_method_t vmbus_methods[] = {
// 	/* Device interface */
// 	DEVMETHOD(device_identify,		vmbus_identify),
// 	DEVMETHOD(device_probe,			vmbus_probe),
// 	DEVMETHOD(device_attach,		vmbus_attach),
// 	DEVMETHOD(device_detach,		vmbus_detach),
// 	DEVMETHOD(device_shutdown,		bus_generic_shutdown),
// 	DEVMETHOD(device_suspend,		bus_generic_suspend),
// 	DEVMETHOD(device_resume,		bus_generic_resume),

// 	/* Bus interface */
// 	DEVMETHOD(bus_add_child,		bus_generic_add_child),
// 	DEVMETHOD(bus_print_child,		bus_generic_print_child),
// 	DEVMETHOD(bus_read_ivar,		vmbus_read_ivar),
// 	DEVMETHOD(bus_child_pnpinfo,		vmbus_child_pnpinfo),
// 	DEVMETHOD(bus_alloc_resource,		vmbus_alloc_resource),
// 	DEVMETHOD(bus_release_resource,		bus_generic_release_resource),
// 	DEVMETHOD(bus_activate_resource,	bus_generic_activate_resource),
// 	DEVMETHOD(bus_deactivate_resource,	bus_generic_deactivate_resource),
// 	DEVMETHOD(bus_setup_intr,		bus_generic_setup_intr),
// 	DEVMETHOD(bus_teardown_intr,		bus_generic_teardown_intr),
// #if __FreeBSD_version >= 1100000
// 	DEVMETHOD(bus_get_cpus,			bus_generic_get_cpus),
// #endif

// 	/* pcib interface */
// 	DEVMETHOD(pcib_alloc_msi,		vmbus_alloc_msi),
// 	DEVMETHOD(pcib_release_msi,		vmbus_release_msi),
// 	DEVMETHOD(pcib_alloc_msix,		vmbus_alloc_msix),
// 	DEVMETHOD(pcib_release_msix,		vmbus_release_msix),
// 	DEVMETHOD(pcib_map_msi,			vmbus_map_msi),

// 	/* Vmbus interface */
// 	DEVMETHOD(vmbus_get_version,		vmbus_get_version_method),
// 	DEVMETHOD(vmbus_probe_guid,		vmbus_probe_guid_method),
// 	DEVMETHOD(vmbus_get_vcpu_id,		vmbus_get_vcpu_id_method),
// 	DEVMETHOD(vmbus_get_event_taskq,	vmbus_get_eventtq_method),

// 	DEVMETHOD_END
// };

// static driver_t vmbus_driver = {
// 	"vmbus",
// 	vmbus_methods,
// 	sizeof(struct vmbus_softc)
// };

// static devclass_t vmbus_devclass;

// DRIVER_MODULE(vmbus, pcib, vmbus_driver, vmbus_devclass, NULL, NULL);
// DRIVER_MODULE(vmbus, acpi_syscontainer, vmbus_driver, vmbus_devclass,
//     NULL, NULL);

// MODULE_DEPEND(vmbus, acpi, 1, 1, 1);
// MODULE_DEPEND(vmbus, pci, 1, 1, 1);
// MODULE_VERSION(vmbus, 1);

static __inline struct vmbus_softc *
vmbus_get_softc(void)
{
	return vmbus_sc;
}

void
vmbus_msghc_reset(struct vmbus_msghc *mh, size_t dsize)
{
	struct hypercall_postmsg_in *inprm;

	if (dsize > HYPERCALL_POSTMSGIN_DSIZE_MAX)
		panic("invalid data size %zu", dsize);

	inprm = vmbus_xact_req_data(mh->mh_xact);
	memset(inprm, 0, HYPERCALL_POSTMSGIN_SIZE);
	inprm->hc_connid = VMBUS_CONNID_MESSAGE;
	inprm->hc_msgtype = HYPERV_MSGTYPE_CHANNEL;
	inprm->hc_dsize = dsize;
}

struct vmbus_msghc *
vmbus_msghc_get(struct vmbus_softc *sc, size_t dsize)
{
	struct vmbus_msghc *mh;
	struct vmbus_xact *xact;

	// uk_pr_info("vmbus_msghc_get start\n");

	if (dsize > HYPERCALL_POSTMSGIN_DSIZE_MAX)
		panic("invalid data size %zu", dsize);

	xact = vmbus_xact_get(sc->vmbus_xc,
	    dsize + __offsetof(struct hypercall_postmsg_in, hc_data[0]));
	if (xact == NULL)
		return (NULL);

	mh = vmbus_xact_priv(xact, sizeof(*mh));
	mh->mh_xact = xact;

	vmbus_msghc_reset(mh, dsize);
	// uk_pr_info("vmbus_msghc_get end\n");
	return (mh);
}

void
vmbus_msghc_put(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{
	// uk_pr_info("vmbus_msghc_put start\n");
	vmbus_xact_put(mh->mh_xact);
	// uk_pr_info("vmbus_msghc_put end\n");
}

void *
vmbus_msghc_dataptr(struct vmbus_msghc *mh)
{
	struct hypercall_postmsg_in *inprm;

	// uk_pr_info("vmbus_msghc_dataptr start\n");
	inprm = vmbus_xact_req_data(mh->mh_xact);
	// uk_pr_info("vmbus_msghc_dataptr end\n");
	return (inprm->hc_data);
}

int
vmbus_msghc_exec_noresult(struct vmbus_msghc *mh)
{
	// sbintime_t time = SBT_1MS;
	int time = 100;
	volatile int i;
	struct hypercall_postmsg_in *inprm;
	bus_addr_t inprm_paddr;
	int ii;

	// uk_pr_info("vmbus_msghc_exec_noresult\n");

	inprm = vmbus_xact_req_data(mh->mh_xact);
	inprm_paddr = vmbus_xact_req_paddr(mh->mh_xact);
	// uk_pr_info("vmbus_msghc_exec_noresult inprm: %p, inprm_paddr: %lx\n", inprm, inprm_paddr);

	/*
	 * Save the input parameter so that we could restore the input
	 * parameter if the Hypercall failed.
	 *
	 * XXX
	 * Is this really necessary?!  i.e. Will the Hypercall ever
	 * overwrite the input parameter?
	 */
	memcpy(&mh->mh_inprm_save, inprm, HYPERCALL_POSTMSGIN_SIZE);

	/*
	 * In order to cope with transient failures, e.g. insufficient
	 * resources on host side, we retry the post message Hypercall
	 * several times.  20 retries seem sufficient.
	 */
#define HC_RETRY_MAX	20

	for (i = 0; i < HC_RETRY_MAX; ++i) {
		uint64_t status;
		__nsec start, now;

		status = hypercall_post_message(inprm_paddr);
		// uk_pr_info("vmbus_msghc_exec_noresult %lu\n", status);
		if (status == HYPERCALL_STATUS_SUCCESS)
			return 0;
		// pause_sbt("hcpmsg", time, 0, C_HARDCLOCK);
		// if (time < SBT_1S * 2)
		// 	time *= 2;
		start = ukplat_monotonic_clock();
		do {
			now = ukplat_monotonic_clock();
		} while (now < start + time);

		time *= 2;

		/* Restore input parameter and try again */
		memcpy(inprm, &mh->mh_inprm_save, HYPERCALL_POSTMSGIN_SIZE);
	}

#undef HC_RETRY_MAX

	// uk_pr_info("vmbus_msghc_exec_noresult error: EIO\n");
 
	return EIO;
}

int
vmbus_msghc_exec(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{
	int error;

	// uk_pr_debug("[%s] start\n", __func__);
	vmbus_xact_activate(mh->mh_xact);
	error = vmbus_msghc_exec_noresult(mh);
	if (error)
		vmbus_xact_deactivate(mh->mh_xact);
	// uk_pr_debug("[%s] end\n", __func__);
	return error;
}

void
vmbus_msghc_exec_cancel(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{

	vmbus_xact_deactivate(mh->mh_xact);
}

const struct vmbus_message *
vmbus_msghc_wait_result(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{
	size_t resp_len;

	// uk_pr_info("[%s] enter\n", __func__);
	return (vmbus_xact_wait(mh->mh_xact, &resp_len));
}

const struct vmbus_message *
vmbus_msghc_poll_result(struct vmbus_softc *sc __unused, struct vmbus_msghc *mh)
{
	size_t resp_len;

	return (vmbus_xact_poll(mh->mh_xact, &resp_len));
}

void
vmbus_msghc_wakeup(struct vmbus_softc *sc, const struct vmbus_message *msg)
{
	uk_pr_info("[vmbus_msghc_wakeup] msg: %p start\n", msg);
	vmbus_xact_ctx_wakeup(sc->vmbus_xc, msg, sizeof(*msg));
	uk_pr_info("[vmbus_msghc_wakeup] msg: %p end\n", msg);
}

uint32_t
vmbus_gpadl_alloc(struct vmbus_softc *sc)
{
	uint32_t gpadl;

again:
	gpadl = atomic_fetchadd_int(&sc->vmbus_gpadl, 1);
	if (gpadl == 0)
		goto again;
	return (gpadl);
}

// /* Used for Hyper-V socket when guest client connects to host */
// int
// vmbus_req_tl_connect(struct hyperv_guid *guest_srv_id,
//     struct hyperv_guid *host_srv_id)
// {
// 	struct vmbus_softc *sc = vmbus_get_softc();
// 	struct vmbus_chanmsg_tl_connect *req;
// 	struct vmbus_msghc *mh;
// 	int error;

// 	if (!sc)
// 		return ENXIO;

// 	mh = vmbus_msghc_get(sc, sizeof(*req));
// 	if (mh == NULL) {
// 		device_printf(sc->vmbus_dev,
// 		    "can not get msg hypercall for tl connect\n");
// 		return ENXIO;
// 	}

// 	req = vmbus_msghc_dataptr(mh);
// 	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_TL_CONN;
// 	req->guest_endpoint_id = *guest_srv_id;
// 	req->host_service_id = *host_srv_id;

// 	error = vmbus_msghc_exec_noresult(mh);
// 	vmbus_msghc_put(sc, mh);

// 	if (error) {
// 		device_printf(sc->vmbus_dev,
// 		    "tl connect msg hypercall failed\n");
// 	}

// 	return error;
// }

static int
vmbus_connect(struct vmbus_softc *sc, uint32_t version)
{
	struct vmbus_chanmsg_connect *req;
	const struct vmbus_message *msg;
	struct vmbus_msghc *mh;
	int error, done = 0;

	uk_pr_info("vmbus_connect start\n");
	mh = vmbus_msghc_get(sc, sizeof(*req));
	if (mh == NULL) {
		uk_pr_info("vmbus_connect end error ENXIO\n");
		return ENXIO;
	}

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CONNECT;
	req->chm_ver = version;
	req->chm_evtflags = (uint64_t) sc->vmbus_evtflags_paddr;
	req->chm_mnf1 = (uint64_t) sc->vmbus_mnf1_paddr;
	req->chm_mnf2 = (uint64_t) sc->vmbus_mnf2_paddr;

	uk_pr_info("vmbus_connect req chm_ver:%d, chm_evtflags: %lu, chm_mnf1: %lu, chm_mnf2: %lu\n", req->chm_ver, req->chm_evtflags, req->chm_mnf1, req->chm_mnf2);

	error = vmbus_msghc_exec(sc, mh);
	if (error) {
		vmbus_msghc_put(sc, mh);
		uk_pr_info("vmbus_connect end error\n");
		return error;
	}

	msg = vmbus_msghc_wait_result(sc, mh);
	done = ((const struct vmbus_chanmsg_connect_resp *)
	    msg->msg_data)->chm_done;

	vmbus_msghc_put(sc, mh);

	uk_pr_info("vmbus_connect end\n");
	return (done ? 0 : EOPNOTSUPP);
}

static int
vmbus_init(struct vmbus_softc *sc)
{
	int i;
	uk_pr_info("vmbus_init start\n");
	uk_pr_info("[vmbus_init] nitems(vmbus_version: %d\n",
		nitems(vmbus_version));
	for (i = 0; i < nitems(vmbus_version); ++i) {
		int error;

		error = vmbus_connect(sc, vmbus_version[i]);
		if (!error) {
			vmbus_current_version = vmbus_version[i];
			sc->vmbus_version = vmbus_version[i];
			device_printf(sc->vmbus_dev, "version %u.%u\n",
			    VMBUS_VERSION_MAJOR(sc->vmbus_version),
			    VMBUS_VERSION_MINOR(sc->vmbus_version));
			return 0;
		}
	}
	uk_pr_info("vmbus_init end\n");
	return ENXIO;
}

// static void
// vmbus_disconnect(struct vmbus_softc *sc)
// {
// 	struct vmbus_chanmsg_disconnect *req;
// 	struct vmbus_msghc *mh;
// 	int error;

// 	mh = vmbus_msghc_get(sc, sizeof(*req));
// 	if (mh == NULL) {
// 		device_printf(sc->vmbus_dev,
// 		    "can not get msg hypercall for disconnect\n");
// 		return;
// 	}

// 	req = vmbus_msghc_dataptr(mh);
// 	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_DISCONNECT;

// 	error = vmbus_msghc_exec_noresult(mh);
// 	vmbus_msghc_put(sc, mh);

// 	if (error) {
// 		device_printf(sc->vmbus_dev,
// 		    "disconnect msg hypercall failed\n");
// 	}
// }

static int
vmbus_req_channels(struct vmbus_softc *sc)
{
	struct vmbus_chanmsg_chrequest *req;
	struct vmbus_msghc *mh;
	int error;

	uk_pr_info("[vmbus_req_channels] start\n");
	mh = vmbus_msghc_get(sc, sizeof(*req));
	if (mh == NULL)
		return ENXIO;

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CHREQUEST;

	error = vmbus_msghc_exec_noresult(mh);
	vmbus_msghc_put(sc, mh);

	uk_pr_info("[vmbus_req_channels] end error: %d\n", error);
	return error;
}

static void
vmbus_scan_done_task(void *xsc)
{
	struct vmbus_softc *sc = xsc;

	uk_pr_info("[%s] start\n", __func__);

	// bus_topo_lock();
	sc->vmbus_scandone = true;
	// bus_topo_unlock();
	wakeup(&sc->vmbus_scandone_wq);

	uk_pr_info("[%s] end\n", __func__);
}

static void
vmbus_scan_done(struct vmbus_softc *sc,
    const struct vmbus_message *msg __unused)
{
	uk_pr_info("[%s] start\n", __func__);
	// taskqueue_enqueue(sc->vmbus_devtq, &sc->vmbus_scandone_task);
	sc->vmbus_dev_thread = uk_thread_create("vmbus_dev", sc->vmbus_scandone_task.ta_func, sc->vmbus_scandone_task.ta_context);
	if (PTRISERR(sc->vmbus_dev_thread))
		uk_pr_info("[%s] Error creating thread: %d\n", __func__, PTR2ERR(sc->vmbus_dev_thread));
	uk_pr_info("[%s] end\n", __func__);
}

static int
vmbus_scan(struct vmbus_softc *sc)
{
	int error;

	uk_pr_info("[vmbus_scan] start\n");

	/*
	 * Identify, probe and attach for non-channel devices.
	 */
	//bus_generic_probe(sc->vmbus_dev);
	//bus_generic_attach(sc->vmbus_dev);

	/*
	 * This taskqueue serializes vmbus devices' attach and detach
	 * for channel offer and rescind messages.
	 */
	// sc->vmbus_devtq = taskqueue_create("vmbus dev", M_WAITOK,
	//     taskqueue_thread_enqueue, &sc->vmbus_devtq);
	// taskqueue_start_threads(&sc->vmbus_devtq, 1, PI_NET, "vmbusdev");
	TASK_INIT(&sc->vmbus_scandone_task, 0, vmbus_scan_done_task, sc);

	/*
	 * This taskqueue handles sub-channel detach, so that vmbus
	 * device's detach running in vmbus_devtq can drain its sub-
	 * channels.
	 */
	// sc->vmbus_subchtq = taskqueue_create("vmbus subch", M_WAITOK,
	//     taskqueue_thread_enqueue, &sc->vmbus_subchtq);
	// taskqueue_start_threads(&sc->vmbus_subchtq, 1, PI_NET, "vmbussch");

	/*
	 * Start vmbus scanning.
	 */
	error = vmbus_req_channels(sc);
	if (error) {
		device_printf(sc->vmbus_dev, "channel request failed: %d\n",
		    error);
		return (error);
	}

	/*
	 * Wait for all vmbus devices from the initial channel offers to be
	 * attached.
	 */
	//bus_topo_assert();
	// while (!sc->vmbus_scandone) {
		// mtx_sleep(&sc->vmbus_scandone, bus_topo_mtx(), 0, "vmbusdev", 0);
		// mtx_sleep(&sc->vmbus_scandone_wq, sc->vmbus_scandone, NULL, 0, "vmbusdev", 0);
	// }
	while (!(sc->vmbus_scandone && !sc->vmbus_scancount && sc->vmbus_probedone)) {
		uk_pr_debug("[%s] sc->vmbus_scandone: %d, sc->vmbus_scancount: %d, sc->vmbus_probedone: %d\n", __func__, sc->vmbus_scandone, sc->vmbus_scancount, sc->vmbus_probedone);
		//mtx_sleep(&sc->vmbus_scandone, bus_topo_mtx(), 0, "vmbusdev", 0);
		mtx_sleep(&sc->vmbus_scandone_wq, (sc->vmbus_scandone && !sc->vmbus_scancount && sc->vmbus_probedone), NULL, 0, "vmbusdev", 0);
	}

	if (bootverbose) {
		device_printf(sc->vmbus_dev, "device scan, probe and attach "
		    "done\n");
	}
	uk_pr_info("[vmbus_scan] end\n");
	return (0);
}

// static void
// vmbus_scan_teardown(struct vmbus_softc *sc)
// {

// 	bus_topo_assert();
// 	if (sc->vmbus_devtq != NULL) {
// 		bus_topo_unlock();
// 		taskqueue_free(sc->vmbus_devtq);
// 		bus_topo_lock();
// 		sc->vmbus_devtq = NULL;
// 	}
// 	if (sc->vmbus_subchtq != NULL) {
// 		bus_topo_unlock();
// 		taskqueue_free(sc->vmbus_subchtq);
// 		bus_topo_lock();
// 		sc->vmbus_subchtq = NULL;
// 	}
// }

static void
vmbus_chanmsg_handle(struct vmbus_softc *sc, const struct vmbus_message *msg)
{
	vmbus_chanmsg_proc_t msg_proc;
	uint32_t msg_type;

	uk_pr_info("[%s] start\n", __func__);

	msg_type = ((const struct vmbus_chanmsg_hdr *)msg->msg_data)->chm_type;
	if (msg_type >= VMBUS_CHANMSG_TYPE_MAX) {
		device_printf(sc->vmbus_dev, "unknown message type 0x%x\n",
		    msg_type);
		return;
	}

	msg_proc = vmbus_chanmsg_handlers[msg_type];
	if (msg_proc != NULL)
		msg_proc(sc, msg);

	/* Channel specific processing */
	vmbus_chan_msgproc(sc, msg);

	uk_pr_info("[%s] end\n", __func__);
}

void
vmbus_msg_task(void *xsc)
{
	struct vmbus_softc *sc = xsc;
	volatile struct vmbus_message *msg;

	uk_pr_info("[%s] start\n", __func__);

	msg = VMBUS_PCPU_GET(sc, message, curcpu) + VMBUS_SINT_MESSAGE;
	for (;;) { 
		if (msg->msg_type == HYPERV_MSGTYPE_NONE) {
			uk_pr_info("[%s] HYPERV_MSGTYPE_NONE\n", __func__);
			/* No message */
			break;
		} else if (msg->msg_type == HYPERV_MSGTYPE_CHANNEL) {
			uk_pr_info("[%s] HYPERV_MSGTYPE_CHANNEL\n", __func__);
			/* Channel message */
			vmbus_chanmsg_handle(sc,
			    __DEVOLATILE(const struct vmbus_message *, msg));
		}

		msg->msg_type = HYPERV_MSGTYPE_NONE;
		/*
		 * Make sure the write to msg_type (i.e. set to
		 * HYPERV_MSGTYPE_NONE) happens before we read the
		 * msg_flags and EOMing. Otherwise, the EOMing will
		 * not deliver any more messages since there is no
		 * empty slot
		 *
		 * NOTE:
		 * mb() is used here, since atomic_thread_fence_seq_cst()
		 * will become compiler fence on UP kernel.
		 */
		mb();
		if (msg->msg_flags & VMBUS_MSGFLAG_PENDING) {
			/*
			 * This will cause message queue rescan to possibly
			 * deliver another msg from the hypervisor
			 */
			uk_pr_info("[%s] message queue rescan\n", __func__);
			wrmsrl(MSR_HV_EOM, 0);
		}
	}

	uk_pr_info("[%s] end\n", __func__);
}

// static __inline int
// vmbus_handle_intr1(struct vmbus_softc *sc, struct trapframe *frame, int cpu)
static __inline int
vmbus_handle_intr1(struct vmbus_softc *sc, int cpu)
{
	volatile struct vmbus_message *msg;
	struct vmbus_message *msg_base;

	uk_pr_info("[vmbus_handle_intr1] start\n");

	msg_base = VMBUS_PCPU_GET(sc, message, cpu);

	/*
	 * Check event timer.
	 *
	 * TODO: move this to independent IDT vector.
	 */
	msg = msg_base + VMBUS_SINT_TIMER;
	if (msg->msg_type == HYPERV_MSGTYPE_TIMER_EXPIRED) {
		msg->msg_type = HYPERV_MSGTYPE_NONE;

		uk_pr_info("[vmbus_handle_intr1] timer expired\n");
		// vmbus_et_intr(frame);

		/*
		 * Make sure the write to msg_type (i.e. set to
		 * HYPERV_MSGTYPE_NONE) happens before we read the
		 * msg_flags and EOMing. Otherwise, the EOMing will
		 * not deliver any more messages since there is no
		 * empty slot
		 *
		 * NOTE:
		 * mb() is used here, since atomic_thread_fence_seq_cst()
		 * will become compiler fence on UP kernel.
		 */
		mb();
		if (msg->msg_flags & VMBUS_MSGFLAG_PENDING) {
			/*
			 * This will cause message queue rescan to possibly
			 * deliver another msg from the hypervisor
			 */
			wrmsrl(MSR_HV_EOM, 0);
		}
	}
	uk_pr_info("[vmbus_handle_intr1] Before vmbus_event_proc sc->vmbus_event_proc: %p\n", sc->vmbus_event_proc);
	/*
	 * Check events.  Hot path for network and storage I/O data; high rate.
	 *
	 * NOTE:
	 * As recommended by the Windows guest fellows, we check events before
	 * checking messages.
	 */
	sc->vmbus_event_proc(sc, cpu);

	uk_pr_info("[vmbus_handle_intr1] After vmbus_event_proc\n");
	/*
	 * Check messages.  Mainly management stuffs; ultra low rate.
	 */
	msg = msg_base + VMBUS_SINT_MESSAGE;
	uk_pr_info("[vmbus_handle_intr1] msg: %p, msg->msg_type: %d\n", msg, msg->msg_type);
	if (__predict_false(msg->msg_type != HYPERV_MSGTYPE_NONE)) {
		// taskqueue_enqueue(VMBUS_PCPU_GET(sc, message_tq, cpu),
		//     VMBUS_PCPU_PTR(sc, message_task, cpu));
		
		// VMBUS_PCPU_GET(sc, message_thread, cpu) = uk_thread_create("hvmsg0", VMBUS_PCPU_GET(sc, message_task, cpu), NULL);
		VMBUS_PCPU_GET(sc, message_thread, cpu) = uk_thread_create("hvmsg0", vmbus_msg_task, sc);
		if (PTRISERR(VMBUS_PCPU_GET(sc, message_thread, cpu)))
			return PTR2ERR(VMBUS_PCPU_GET(sc, message_thread, cpu));
	}

	uk_pr_info("[vmbus_handle_intr1] end\n");

	// return (FILTER_HANDLED);
	return 0;
}

// void
// vmbus_handle_intr(struct trapframe *trap_frame)
void
vmbus_handle_intr(void)

{
	struct vmbus_softc *sc = vmbus_get_softc();
	int cpu = curcpu;
	uk_pr_info("[vmbus_handle_intr] sc: %p, intr_cnt: %lu\n", sc, *(VMBUS_PCPU_GET(sc, intr_cnt, cpu)));
// 	/*
// 	 * Disable preemption.
// 	 */
// 	critical_enter();

	/*
	 * Do a little interrupt counting.
	 */
 	(*VMBUS_PCPU_GET(sc, intr_cnt, cpu))++;

	//vmbus_handle_intr1(sc, trap_frame, cpu);
	vmbus_handle_intr1(sc, cpu);

// 	/*
// 	 * Enable preemption.
// 	 */
// 	critical_exit();
}

static void
vmbus_synic_setup(void *xsc)
{
	struct vmbus_softc *sc = xsc;
	int cpu = curcpu;
	uint64_t val, orig;
	uint32_t sint;

	if (hyperv_features & CPUID_HV_MSR_VP_INDEX) {
		/* Save virtual processor id. */
		VMBUS_PCPU_GET(sc, vcpuid, cpu) = rdmsrl(MSR_HV_VP_INDEX);
	} else {
		/* Set virtual processor id to 0 for compatibility. */
		VMBUS_PCPU_GET(sc, vcpuid, cpu) = 0;
	}

	/*
	 * Setup the SynIC message.
	 */
	orig = rdmsrl(MSR_HV_SIMP);
	val = MSR_HV_SIMP_ENABLE | (orig & MSR_HV_SIMP_RSVD_MASK) |
	    (((__paddr_t)VMBUS_PCPU_GET(sc, message, cpu) >> PAGE_SHIFT) <<
	     MSR_HV_SIMP_PGSHIFT);
	wrmsrl(MSR_HV_SIMP, val);

	/*
	 * Setup the SynIC event flags.
	 */
	orig = rdmsrl(MSR_HV_SIEFP);
	val = MSR_HV_SIEFP_ENABLE | (orig & MSR_HV_SIEFP_RSVD_MASK) |
	    (((__paddr_t)VMBUS_PCPU_GET(sc, event_flags, cpu)
	      >> PAGE_SHIFT) << MSR_HV_SIEFP_PGSHIFT);
	wrmsrl(MSR_HV_SIEFP, val);


	/*
	 * Configure and unmask SINT for message and event flags.
	 */
	sint = MSR_HV_SINT0 + VMBUS_SINT_MESSAGE;
	orig = rdmsrl(sint);
	val = sc->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
	    (orig & MSR_HV_SINT_RSVD_MASK);
	wrmsrl(sint, val);

	/*
	 * Configure and unmask SINT for timer.
	 */
	sint = MSR_HV_SINT0 + VMBUS_SINT_TIMER;
	orig = rdmsrl(sint);
	val = sc->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
	    (orig & MSR_HV_SINT_RSVD_MASK);
	wrmsrl(sint, val);

	/*
	 * All done; enable SynIC.
	 */
	orig = rdmsrl(MSR_HV_SCONTROL);
	val = MSR_HV_SCTRL_ENABLE | (orig & MSR_HV_SCTRL_RSVD_MASK);
	wrmsrl(MSR_HV_SCONTROL, val);
	uint64_t val_new = rdmsrl(MSR_HV_SCONTROL);
	uk_pr_info("val: %lx, val_new: %lx\n", val, val_new);
}

// static void
// vmbus_synic_teardown(void *arg)
// {
// 	uint64_t orig;
// 	uint32_t sint;

// 	/*
// 	 * Disable SynIC.
// 	 */
// 	orig = rdmsrl(MSR_HV_SCONTROL);
// 	wrmsrl(MSR_HV_SCONTROL, (orig & MSR_HV_SCTRL_RSVD_MASK));

// 	/*
// 	 * Mask message and event flags SINT.
// 	 */
// 	sint = MSR_HV_SINT0 + VMBUS_SINT_MESSAGE;
// 	orig = rdmsrl(sint);
// 	wrmsrl(sint, orig | MSR_HV_SINT_MASKED);

// 	/*
// 	 * Mask timer SINT.
// 	 */
// 	sint = MSR_HV_SINT0 + VMBUS_SINT_TIMER;
// 	orig = rdmsrl(sint);
// 	wrmsrl(sint, orig | MSR_HV_SINT_MASKED);

// 	/*
// 	 * Teardown SynIC message.
// 	 */
// 	orig = rdmsrl(MSR_HV_SIMP);
// 	wrmsrl(MSR_HV_SIMP, (orig & MSR_HV_SIMP_RSVD_MASK));

// 	/*
// 	 * Teardown SynIC event flags.
// 	 */
// 	orig = rdmsrl(MSR_HV_SIEFP);
// 	wrmsrl(MSR_HV_SIEFP, (orig & MSR_HV_SIEFP_RSVD_MASK));
// }

static int
vmbus_page_alloc(struct vmbus_softc *sc)
{
	uint8_t *evtflags;
	int cpu;
	uk_pr_info("[%s] start\n", __func__);

// 	CPU_FOREACH(cpu) {
		cpu = 0;
		void *ptr;

		/*
		 * Per-cpu messages and event flags.
		 */
// 		ptr = hyperv_dmamem_alloc(parent_dtag, PAGE_SIZE, 0,
// 		    PAGE_SIZE, VMBUS_PCPU_PTR(sc, message_dma, cpu),
// 		    BUS_DMA_WAITOK | BUS_DMA_ZERO);
		ptr = hyperv_mem_alloc(sc->a, PAGE_SIZE);
		if (ptr == NULL)
			return ENOMEM;
		VMBUS_PCPU_GET(sc, message, cpu) = ptr;
		VMBUS_PCPU_GET(sc, message_paddr, cpu) = ukplat_virt_to_phys(ptr);

// 		ptr = hyperv_dmamem_alloc(parent_dtag, PAGE_SIZE, 0,
// 		    PAGE_SIZE, VMBUS_PCPU_PTR(sc, event_flags_dma, cpu),
// 		    BUS_DMA_WAITOK | BUS_DMA_ZERO);
		ptr = hyperv_mem_alloc(sc->a, PAGE_SIZE);
		if (ptr == NULL)
			return ENOMEM;
		VMBUS_PCPU_GET(sc, event_flags, cpu) = ptr;
		VMBUS_PCPU_GET(sc, event_flags_paddr, cpu) = ukplat_virt_to_phys(ptr);
// 	}

// 	evtflags = hyperv_dmamem_alloc(parent_dtag, PAGE_SIZE, 0,
// 	    PAGE_SIZE, &sc->vmbus_evtflags_dma, BUS_DMA_WAITOK | BUS_DMA_ZERO);
	evtflags = hyperv_mem_alloc(sc->a, PAGE_SIZE);
	if (evtflags == NULL)
		return ENOMEM;
	sc->vmbus_rx_evtflags = (u_long *)evtflags;
	sc->vmbus_tx_evtflags = (u_long *)(evtflags + (PAGE_SIZE / 2));
	sc->vmbus_evtflags = evtflags;
	sc->vmbus_evtflags_paddr = ukplat_virt_to_phys(evtflags);

// 	sc->vmbus_mnf1 = hyperv_dmamem_alloc(parent_dtag, PAGE_SIZE, 0,
// 	    PAGE_SIZE, &sc->vmbus_mnf1_dma, BUS_DMA_WAITOK | BUS_DMA_ZERO);
	sc->vmbus_mnf1 = hyperv_mem_alloc(sc->a, PAGE_SIZE);
	if (sc->vmbus_mnf1 == NULL)
		return ENOMEM;
	sc->vmbus_mnf1_paddr = ukplat_virt_to_phys(sc->vmbus_mnf1);

// 	sc->vmbus_mnf2 = hyperv_dmamem_alloc(parent_dtag, PAGE_SIZE, 0,
// 	    sizeof(struct vmbus_mnf), &sc->vmbus_mnf2_dma,
// 	    BUS_DMA_WAITOK | BUS_DMA_ZERO);
	sc->vmbus_mnf2 = hyperv_mem_alloc(sc->a, PAGE_SIZE);
	if (sc->vmbus_mnf2 == NULL)
		return ENOMEM;
	sc->vmbus_mnf2_paddr = ukplat_virt_to_phys(sc->vmbus_mnf2);

	uk_pr_info("[%s] end\n", __func__);
	return 0;
}

// static void
// vmbus_dma_free(struct vmbus_softc *sc)
// {
// 	int cpu;

// 	if (sc->vmbus_evtflags != NULL) {
// 		hyperv_dmamem_free(&sc->vmbus_evtflags_dma, sc->vmbus_evtflags);
// 		sc->vmbus_evtflags = NULL;
// 		sc->vmbus_rx_evtflags = NULL;
// 		sc->vmbus_tx_evtflags = NULL;
// 	}
// 	if (sc->vmbus_mnf1 != NULL) {
// 		hyperv_dmamem_free(&sc->vmbus_mnf1_dma, sc->vmbus_mnf1);
// 		sc->vmbus_mnf1 = NULL;
// 	}
// 	if (sc->vmbus_mnf2 != NULL) {
// 		hyperv_dmamem_free(&sc->vmbus_mnf2_dma, sc->vmbus_mnf2);
// 		sc->vmbus_mnf2 = NULL;
// 	}

// 	CPU_FOREACH(cpu) {
// 		if (VMBUS_PCPU_GET(sc, message, cpu) != NULL) {
// 			hyperv_dmamem_free(
// 			    VMBUS_PCPU_PTR(sc, message_dma, cpu),
// 			    VMBUS_PCPU_GET(sc, message, cpu));
// 			VMBUS_PCPU_GET(sc, message, cpu) = NULL;
// 		}
// 		if (VMBUS_PCPU_GET(sc, event_flags, cpu) != NULL) {
// 			hyperv_dmamem_free(
// 			    VMBUS_PCPU_PTR(sc, event_flags_dma, cpu),
// 			    VMBUS_PCPU_GET(sc, event_flags, cpu));
// 			VMBUS_PCPU_GET(sc, event_flags, cpu) = NULL;
// 		}
// 	}
// }

static int
vmbus_intr_setup(struct vmbus_softc *sc)
{
	int cpu;
	
	uk_pr_info("[%s] start\n", __func__);

//	CPU_FOREACH(cpu) {
		cpu = 0;
// 		char buf[MAXCOMLEN + 1];
// 		cpuset_t cpu_mask;

		/* Allocate an interrupt counter for Hyper-V interrupt */
// 		snprintf(buf, sizeof(buf), "cpu%d:hyperv", cpu);
// 		intrcnt_add(buf, VMBUS_PCPU_PTR(sc, intr_cnt, cpu));
		VMBUS_PCPU_GET(sc, intr_cnt, cpu) = uk_malloc(sc->a, sizeof(u_long));

		/*
		 * Setup taskqueue to handle events.  Task will be per-
		 * channel.
		 */
// 		VMBUS_PCPU_GET(sc, event_tq, cpu) = taskqueue_create_fast(
// 		    "hyperv event", M_WAITOK, taskqueue_thread_enqueue,
// 		    VMBUS_PCPU_PTR(sc, event_tq, cpu));
// 		if (vmbus_pin_evttask) {
// 			CPU_SETOF(cpu, &cpu_mask);
// 			taskqueue_start_threads_cpuset(
// 			    VMBUS_PCPU_PTR(sc, event_tq, cpu), 1, PI_NET,
// 			    &cpu_mask, "hvevent%d", cpu);
// 		} else {
// 			taskqueue_start_threads(
// 			    VMBUS_PCPU_PTR(sc, event_tq, cpu), 1, PI_NET,
// 			    "hvevent%d", cpu);
// 		}

		/*
		 * Setup tasks and taskqueues to handle messages.
		 */
// 		VMBUS_PCPU_GET(sc, message_tq, cpu) = taskqueue_create_fast(
// 		    "hyperv msg", M_WAITOK, taskqueue_thread_enqueue,
// 		    VMBUS_PCPU_PTR(sc, message_tq, cpu));
// 		CPU_SETOF(cpu, &cpu_mask);
// 		taskqueue_start_threads_cpuset(
// 		    VMBUS_PCPU_PTR(sc, message_tq, cpu), 1, PI_NET, &cpu_mask,
// 		    "hvmsg%d", cpu);
		TASK_INIT(VMBUS_PCPU_PTR(sc, message_task, cpu), 0,
		    vmbus_msg_task, sc);
	// }

// #if defined(__amd64__) && defined(KLD_MODULE)
// 	pmap_pti_add_kva(VMBUS_ISR_ADDR, VMBUS_ISR_ADDR + PAGE_SIZE, true);
// #endif

// 	/*
// 	 * All Hyper-V ISR required resources are setup, now let's find a
// 	 * free IDT vector for Hyper-V ISR and set it up.
// 	 */
// 	sc->vmbus_idtvec = lapic_ipi_alloc(pti ? IDTVEC(vmbus_isr_pti) :
// 	    IDTVEC(vmbus_isr));
// 	if (sc->vmbus_idtvec < 0) {
// #if defined(__amd64__) && defined(KLD_MODULE)
// 		pmap_pti_remove_kva(VMBUS_ISR_ADDR, VMBUS_ISR_ADDR + PAGE_SIZE);
// #endif
// 		device_printf(sc->vmbus_dev, "cannot find free IDT vector\n");
// 		return ENXIO;
// 	}
	sc->vmbus_idtvec = 0xef;
	intctrl_clear_irq(sc->vmbus_idtvec);
;
	if (bootverbose) {
		device_printf(sc->vmbus_dev, "vmbus IDT vector %d\n",
		    sc->vmbus_idtvec);
	}
	uk_pr_info("[%s] end\n", __func__);
	return 0;
}

// static void
// vmbus_intr_teardown(struct vmbus_softc *sc)
// {
// 	int cpu;

// 	if (sc->vmbus_idtvec >= 0) {
// 		lapic_ipi_free(sc->vmbus_idtvec);
// 		sc->vmbus_idtvec = -1;
// 	}

// #if defined(__amd64__) && defined(KLD_MODULE)
// 	pmap_pti_remove_kva(VMBUS_ISR_ADDR, VMBUS_ISR_ADDR + PAGE_SIZE);
// #endif

// 	CPU_FOREACH(cpu) {
// 		if (VMBUS_PCPU_GET(sc, event_tq, cpu) != NULL) {
// 			taskqueue_free(VMBUS_PCPU_GET(sc, event_tq, cpu));
// 			VMBUS_PCPU_GET(sc, event_tq, cpu) = NULL;
// 		}
// 		if (VMBUS_PCPU_GET(sc, message_tq, cpu) != NULL) {
// 			taskqueue_drain(VMBUS_PCPU_GET(sc, message_tq, cpu),
// 			    VMBUS_PCPU_PTR(sc, message_task, cpu));
// 			taskqueue_free(VMBUS_PCPU_GET(sc, message_tq, cpu));
// 			VMBUS_PCPU_GET(sc, message_tq, cpu) = NULL;
// 		}
// 	}
// }

// static int
// vmbus_read_ivar(device_t dev, device_t child, int index, uintptr_t *result)
// {
// 	return (ENOENT);
// }

// static int
// vmbus_child_pnpinfo(device_t dev, device_t child, struct sbuf *sb)
// {
// 	const struct vmbus_channel *chan;
// 	char guidbuf[HYPERV_GUID_STRLEN];

// 	chan = vmbus_get_channel(child);
// 	if (chan == NULL) {
// 		/* Event timer device, which does not belong to a channel */
// 		return (0);
// 	}

// 	hyperv_guid2str(&chan->ch_guid_type, guidbuf, sizeof(guidbuf));
// 	sbuf_printf(sb, "classid=%s", guidbuf);

// 	hyperv_guid2str(&chan->ch_guid_inst, guidbuf, sizeof(guidbuf));
// 	sbuf_printf(sb, " deviceid=%s", guidbuf);

// 	return (0);
// }

int
vmbus_add_child(struct vmbus_channel *chan)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	// device_t parent = sc->vmbus_dev;

	uk_pr_info("[vmbus_add_child] chid: %u start\n", chan->ch_id);

	// bus_topo_lock();
	// chan->ch_dev = device_add_child(parent, NULL, -1);
	// if (chan->ch_dev == NULL) {
	// 	bus_topo_unlock();
	// 	device_printf(parent, "device_add_child for chan%u failed\n",
	// 	    chan->ch_id);
	// 	return (ENXIO);
	// }
	// device_set_ivars(chan->ch_dev, chan);
	// device_probe_and_attach(chan->ch_dev);
	// bus_topo_unlock();

	vmbus_probe_device_type(chan);

	uk_pr_info("[vmbus_add_child] chid: %u end\n", chan->ch_id);

	return (0);
}

int
vmbus_delete_child(struct vmbus_channel *chan)
{
	int error = 0;

	uk_pr_info("vmbus_delete_child start\n");

	// bus_topo_lock();
	// if (chan->ch_dev != NULL) {
	// 	error = device_delete_child(chan->ch_vmbus->vmbus_dev,
	// 	    chan->ch_dev);
	// 	chan->ch_dev = NULL;
	// }
	// bus_topo_unlock();

	uk_pr_info("vmbus_delete_child end\n");
	return (error);
}

// static int
// vmbus_sysctl_version(SYSCTL_HANDLER_ARGS)
// {
// 	struct vmbus_softc *sc = arg1;
// 	char verstr[16];

// 	snprintf(verstr, sizeof(verstr), "%u.%u",
// 	    VMBUS_VERSION_MAJOR(sc->vmbus_version),
// 	    VMBUS_VERSION_MINOR(sc->vmbus_version));
// 	return sysctl_handle_string(oidp, verstr, sizeof(verstr), req);
// }

// /*
//  * We need the function to make sure the MMIO resource is allocated from the
//  * ranges found in _CRS.
//  *
//  * For the release function, we can use bus_generic_release_resource().
//  */
// static struct resource *
// vmbus_alloc_resource(device_t dev, device_t child, int type, int *rid,
//     rman_res_t start, rman_res_t end, rman_res_t count, u_int flags)
// {
// 	device_t parent = device_get_parent(dev);
// 	struct resource *res;

// #ifdef NEW_PCIB
// 	if (type == SYS_RES_MEMORY) {
// 		struct vmbus_softc *sc = device_get_softc(dev);

// 		res = pcib_host_res_alloc(&sc->vmbus_mmio_res, child, type,
// 		    rid, start, end, count, flags);
// 	} else
// #endif
// 	{
// 		res = BUS_ALLOC_RESOURCE(parent, child, type, rid, start,
// 		    end, count, flags);
// 	}

// 	return (res);
// }

// static int
// vmbus_alloc_msi(device_t bus, device_t dev, int count, int maxcount, int *irqs)
// {

// 	return (PCIB_ALLOC_MSI(device_get_parent(bus), dev, count, maxcount,
// 	    irqs));
// }

// static int
// vmbus_release_msi(device_t bus, device_t dev, int count, int *irqs)
// {

// 	return (PCIB_RELEASE_MSI(device_get_parent(bus), dev, count, irqs));
// }

// static int
// vmbus_alloc_msix(device_t bus, device_t dev, int *irq)
// {

// 	return (PCIB_ALLOC_MSIX(device_get_parent(bus), dev, irq));
// }

// static int
// vmbus_release_msix(device_t bus, device_t dev, int irq)
// {

// 	return (PCIB_RELEASE_MSIX(device_get_parent(bus), dev, irq));
// }

// static int
// vmbus_map_msi(device_t bus, device_t dev, int irq, uint64_t *addr,
// 	uint32_t *data)
// {

// 	return (PCIB_MAP_MSI(device_get_parent(bus), dev, irq, addr, data));
// }

// static uint32_t
// vmbus_get_version_method(device_t bus, device_t dev)
// {
// 	struct vmbus_softc *sc = device_get_softc(bus);

// 	return sc->vmbus_version;
// }

// static int
// vmbus_probe_guid_method(device_t bus, device_t dev,
//     const struct hyperv_guid *guid)
static int
vmbus_probe_guid_method(device_t dev,
    const struct hyperv_guid *guid)
{
	const struct vmbus_channel *chan = vmbus_get_channel(dev);

	if (memcmp(&chan->ch_guid_type, guid, sizeof(struct hyperv_guid)) == 0)
		return 0;
	return ENXIO;
}

// static uint32_t
// vmbus_get_vcpu_id_method(device_t bus, device_t dev, int cpu)
// {
// 	const struct vmbus_softc *sc = device_get_softc(bus);

// 	return (VMBUS_PCPU_GET(sc, vcpuid, cpu));
// }

// static struct taskqueue *
// vmbus_get_eventtq_method(device_t bus, device_t dev __unused, int cpu)
// {
// 	const struct vmbus_softc *sc = device_get_softc(bus);

// 	KASSERT(cpu >= 0 && cpu < mp_ncpus, ("invalid cpu%d", cpu));
// 	return (VMBUS_PCPU_GET(sc, event_tq, cpu));
// }

// #ifdef NEW_PCIB
// #define VTPM_BASE_ADDR 0xfed40000
// #define FOUR_GB (1ULL << 32)

// enum parse_pass { parse_64, parse_32 };

// struct parse_context {
// 	device_t vmbus_dev;
// 	enum parse_pass pass;
// };

// static ACPI_STATUS
// parse_crs(ACPI_RESOURCE *res, void *ctx)
// {
// 	const struct parse_context *pc = ctx;
// 	device_t vmbus_dev = pc->vmbus_dev;

// 	struct vmbus_softc *sc = device_get_softc(vmbus_dev);
// 	UINT64 start, end;

// 	switch (res->Type) {
// 	case ACPI_RESOURCE_TYPE_ADDRESS32:
// 		start = res->Data.Address32.Address.Minimum;
// 		end = res->Data.Address32.Address.Maximum;
// 		break;

// 	case ACPI_RESOURCE_TYPE_ADDRESS64:
// 		start = res->Data.Address64.Address.Minimum;
// 		end = res->Data.Address64.Address.Maximum;
// 		break;

// 	default:
// 		/* Unused types. */
// 		return (AE_OK);
// 	}

// 	/*
// 	 * We don't use <1MB addresses.
// 	 */
// 	if (end < 0x100000)
// 		return (AE_OK);

// 	/* Don't conflict with vTPM. */
// 	if (end >= VTPM_BASE_ADDR && start < VTPM_BASE_ADDR)
// 		end = VTPM_BASE_ADDR - 1;

// 	if ((pc->pass == parse_32 && start < FOUR_GB) ||
// 	    (pc->pass == parse_64 && start >= FOUR_GB))
// 		pcib_host_res_decodes(&sc->vmbus_mmio_res, SYS_RES_MEMORY,
// 		    start, end, 0);

// 	return (AE_OK);
// }

// static void
// vmbus_get_crs(device_t dev, device_t vmbus_dev, enum parse_pass pass)
// {
// 	struct parse_context pc;
// 	ACPI_STATUS status;

// 	if (bootverbose)
// 		device_printf(dev, "walking _CRS, pass=%d\n", pass);

// 	pc.vmbus_dev = vmbus_dev;
// 	pc.pass = pass;
// 	status = AcpiWalkResources(acpi_get_handle(dev), "_CRS",
// 			parse_crs, &pc);

// 	if (bootverbose && ACPI_FAILURE(status))
// 		device_printf(dev, "_CRS: not found, pass=%d\n", pass);
// }

// static void
// vmbus_get_mmio_res_pass(device_t dev, enum parse_pass pass)
// {
// 	device_t acpi0, parent;

// 	parent = device_get_parent(dev);

// 	acpi0 = device_get_parent(parent);
// 	if (strcmp("acpi0", device_get_nameunit(acpi0)) == 0) {
// 		device_t *children;
// 		int count;

// 		/*
// 		 * Try to locate VMBUS resources and find _CRS on them.
// 		 */
// 		if (device_get_children(acpi0, &children, &count) == 0) {
// 			int i;

// 			for (i = 0; i < count; ++i) {
// 				if (!device_is_attached(children[i]))
// 					continue;

// 				if (strcmp("vmbus_res",
// 				    device_get_name(children[i])) == 0)
// 					vmbus_get_crs(children[i], dev, pass);
// 			}
// 			free(children, M_TEMP);
// 		}

// 		/*
// 		 * Try to find _CRS on acpi.
// 		 */
// 		vmbus_get_crs(acpi0, dev, pass);
// 	} else {
// 		device_printf(dev, "not grandchild of acpi\n");
// 	}

// 	/*
// 	 * Try to find _CRS on parent.
// 	 */
// 	vmbus_get_crs(parent, dev, pass);
// }

// static void
// vmbus_get_mmio_res(device_t dev)
// {
// 	struct vmbus_softc *sc = device_get_softc(dev);
// 	/*
// 	 * We walk the resources twice to make sure that: in the resource
// 	 * list, the 32-bit resources appear behind the 64-bit resources.
// 	 * NB: resource_list_add() uses INSERT_TAIL. This way, when we
// 	 * iterate through the list to find a range for a 64-bit BAR in
// 	 * vmbus_alloc_resource(), we can make sure we try to use >4GB
// 	 * ranges first.
// 	 */
// 	pcib_host_res_init(dev, &sc->vmbus_mmio_res);

// 	vmbus_get_mmio_res_pass(dev, parse_64);
// 	vmbus_get_mmio_res_pass(dev, parse_32);
// }

// /*
//  * On Gen2 VMs, Hyper-V provides mmio space for framebuffer.
//  * This mmio address range is not useable for other PCI devices.
//  * Currently only efifb and vbefb drivers are using this range without
//  * reserving it from system.
//  * Therefore, vmbus driver reserves it before any other PCI device
//  * drivers start to request mmio addresses.
//  */
// static struct resource *hv_fb_res;

// static void
// vmbus_fb_mmio_res(device_t dev)
// {
// 	struct efi_fb *efifb;
// 	struct vbe_fb *vbefb;
// 	rman_res_t fb_start, fb_end, fb_count;
// 	int fb_height, fb_width;
// 	caddr_t kmdp;

// 	struct vmbus_softc *sc = device_get_softc(dev);
// 	int rid = 0;

// 	kmdp = preload_search_by_type("elf kernel");
// 	if (kmdp == NULL)
// 		kmdp = preload_search_by_type("elf64 kernel");
// 	efifb = (struct efi_fb *)preload_search_info(kmdp,
// 	    MODINFO_METADATA | MODINFOMD_EFI_FB);
// 	vbefb = (struct vbe_fb *)preload_search_info(kmdp,
// 	    MODINFO_METADATA | MODINFOMD_VBE_FB);
// 	if (efifb != NULL) {
// 		fb_start = efifb->fb_addr;
// 		fb_end = efifb->fb_addr + efifb->fb_size;
// 		fb_count = efifb->fb_size;
// 		fb_height = efifb->fb_height;
// 		fb_width = efifb->fb_width;
// 	} else if (vbefb != NULL) {
// 		fb_start = vbefb->fb_addr;
// 		fb_end = vbefb->fb_addr + vbefb->fb_size;
// 		fb_count = vbefb->fb_size;
// 		fb_height = vbefb->fb_height;
// 		fb_width = vbefb->fb_width;
// 	} else {
// 		if (bootverbose)
// 			device_printf(dev,
// 			    "no preloaded kernel fb information\n");
// 		/* We are on Gen1 VM, just return. */
// 		return;
// 	}
	
// 	if (bootverbose)
// 		device_printf(dev,
// 		    "fb: fb_addr: %#jx, size: %#jx, "
// 		    "actual size needed: 0x%x\n",
// 		    fb_start, fb_count, fb_height * fb_width);

// 	hv_fb_res = pcib_host_res_alloc(&sc->vmbus_mmio_res, dev,
// 	    SYS_RES_MEMORY, &rid, fb_start, fb_end, fb_count,
// 	    RF_ACTIVE | rman_make_alignment_flags(PAGE_SIZE));

// 	if (hv_fb_res && bootverbose)
// 		device_printf(dev,
// 		    "successfully reserved memory for framebuffer "
// 		    "starting at %#jx, size %#jx\n",
// 		    fb_start, fb_count);
// }

// static void
// vmbus_free_mmio_res(device_t dev)
// {
// 	struct vmbus_softc *sc = device_get_softc(dev);

// 	pcib_host_res_free(dev, &sc->vmbus_mmio_res);

// 	if (hv_fb_res)
// 		hv_fb_res = NULL;
// }
// #endif	/* NEW_PCIB */

// static void
// vmbus_identify(driver_t *driver, device_t parent)
// {

// 	if (device_get_unit(parent) != 0 || vm_guest != VM_GUEST_HV ||
// 	    (hyperv_features & CPUID_HV_MSR_SYNIC) == 0)
// 		return;
// 	device_add_child(parent, "vmbus", -1);
// }

// static int
// vmbus_probe(device_t dev)
// {

// 	if (device_get_unit(dev) != 0 || vm_guest != VM_GUEST_HV ||
// 	    (hyperv_features & CPUID_HV_MSR_SYNIC) == 0)
// 		return (ENXIO);

// 	device_set_desc(dev, "Hyper-V Vmbus");
// 	return (BUS_PROBE_DEFAULT);
// }

/**
 * @brief Main vmbus driver initialization routine.
 *
 * Here, we
 * - initialize the vmbus driver context
 * - setup various driver entry points
 * - invoke the vmbus hv main init routine
 * - get the irq resource
 * - invoke the vmbus to add the vmbus root device
 * - setup the vmbus root device
 * - retrieve the channel offers
 */
static int
vmbus_doattach(struct vmbus_softc *sc)
{
// 	struct sysctl_oid_list *child;
// 	struct sysctl_ctx_list *ctx;
	int ret;
	uk_pr_info("vmbus_doattach start\n");
	if (sc->vmbus_flags & VMBUS_FLAG_ATTACHED) {
		uk_pr_info("vmbus_doattach already attached\n");
		return (0);
	}

// #ifdef NEW_PCIB
// 	vmbus_get_mmio_res(sc->vmbus_dev);
// 	vmbus_fb_mmio_res(sc->vmbus_dev);
// #endif

	sc->vmbus_flags |= VMBUS_FLAG_ATTACHED;

	sc->vmbus_gpadl = VMBUS_GPADL_START;
	mtx_init(&sc->vmbus_prichan_lock, "vmbus prichan", NULL, MTX_DEF);
 	TAILQ_INIT(&sc->vmbus_prichans);
	mtx_init(&sc->vmbus_chan_lock, "vmbus channel", NULL, MTX_DEF);
	TAILQ_INIT(&sc->vmbus_chans);
	// sc->vmbus_chmap = malloc(
	    // sizeof(struct vmbus_channel *) * VMBUS_CHAN_MAX, M_DEVBUF,
	    // M_WAITOK | M_ZERO);
	sc->vmbus_chmap = uk_calloc(sc->a, 1,
	    sizeof(struct vmbus_channel *) * VMBUS_CHAN_MAX);

	/*
	 * Create context for "post message" Hypercalls
	 */
	// sc->vmbus_xc = vmbus_xact_ctx_create(bus_get_dma_tag(sc->vmbus_dev),
	//     HYPERCALL_POSTMSGIN_SIZE, VMBUS_MSG_SIZE,
	//     sizeof(struct vmbus_msghc));
	sc->vmbus_xc = vmbus_xact_ctx_create(sc->a,
	    HYPERCALL_POSTMSGIN_SIZE, VMBUS_MSG_SIZE,
	    sizeof(struct vmbus_msghc));
	if (sc->vmbus_xc == NULL) {
		ret = ENXIO;
		goto cleanup;
	}

	/*
	 * Allocate page stuffs.
	 */
	ret = vmbus_page_alloc(sc);
	if (ret != 0)
		goto cleanup;
	uk_pr_info("vmbus_page_alloc successfull\n");
	/*
	 * Setup interrupt.
	 */
	ret = vmbus_intr_setup(sc);
	if (ret != 0)
		goto cleanup;
	uk_pr_info("vmbus_intr_setup successfull\n");

	/*
	 * Setup SynIC.
	 */
// 	if (bootverbose)
// 		device_printf(sc->vmbus_dev, "smp_started = %d\n", smp_started);
// 	smp_rendezvous(NULL, vmbus_synic_setup, NULL, sc);
	vmbus_synic_setup(sc);
	sc->vmbus_flags |= VMBUS_FLAG_SYNIC;
	uk_pr_info("vmbus_synic_setup successfull\n");

	/*
	 * Initialize vmbus, e.g. connect to Hypervisor.
	 */
	ret = vmbus_init(sc);
	if (ret != 0)
		goto cleanup;
	uk_pr_info("vmbus_init successfull\n");

	if (sc->vmbus_version == VMBUS_VERSION_WS2008 ||
	    sc->vmbus_version == VMBUS_VERSION_WIN7)
		sc->vmbus_event_proc = vmbus_event_proc_compat;
	else
		sc->vmbus_event_proc = vmbus_event_proc;

	ret = vmbus_scan(sc);
	if (ret != 0)
		goto cleanup;
	uk_pr_info("vmbus_scan successfull\n");

// 	ctx = device_get_sysctl_ctx(sc->vmbus_dev);
// 	child = SYSCTL_CHILDREN(device_get_sysctl_tree(sc->vmbus_dev));
// 	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "version",
// 	    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, sc, 0,
// 	    vmbus_sysctl_version, "A", "vmbus version");

	return (ret);

cleanup:
// 	vmbus_scan_teardown(sc);
// 	vmbus_intr_teardown(sc);
// 	vmbus_dma_free(sc);
// 	if (sc->vmbus_xc != NULL) {
// 		vmbus_xact_ctx_destroy(sc->vmbus_xc);
// 		sc->vmbus_xc = NULL;
// 	}
// 	free(__DEVOLATILE(void *, sc->vmbus_chmap), M_DEVBUF);
// 	mtx_destroy(&sc->vmbus_prichan_lock);
// 	mtx_destroy(&sc->vmbus_chan_lock);

	return (ret);
}

static void
vmbus_event_proc_dummy(struct vmbus_softc *sc __unused, int cpu __unused)
{
}

// #ifdef EARLY_AP_STARTUP

static void
vmbus_intrhook(void *xsc)
{
	struct vmbus_softc *sc = xsc;
	uk_pr_info("vmbus_intrhook start");
	if (bootverbose)
		device_printf(sc->vmbus_dev, "intrhook\n");
	vmbus_doattach(sc);
// 	config_intrhook_disestablish(&sc->vmbus_intrhook);
}

// #endif	/* EARLY_AP_STARTUP */

// static int
// vmbus_attach(device_t dev)
static int
vmbus_attach(struct uk_alloc *a)
{
	// vmbus_sc = device_get_softc(dev);
	// vmbus_sc->vmbus_dev = dev;
	vmbus_sc = uk_calloc(a, 1, sizeof(struct vmbus_softc));
	if (vmbus_sc == NULL) {
		uk_pr_info("[vmbus_attach] vmbus_sc alloc failed!");
		return -1;
	}
	vmbus_sc->a = a;
 	uk_waitq_init(&vmbus_sc->vmbus_scandone_wq);

	vmbus_sc->vmbus_idtvec = -1;

	/*
	 * Event processing logic will be configured:
	 * - After the vmbus protocol version negotiation.
	 * - Before we request channel offers.
	 */
	vmbus_sc->vmbus_event_proc = vmbus_event_proc_dummy;

// #ifdef EARLY_AP_STARTUP
// 	/*
// 	 * Defer the real attach until the pause(9) works as expected.
// 	 */
// 	vmbus_sc->vmbus_intrhook.ich_func = vmbus_intrhook;
// 	vmbus_sc->vmbus_intrhook.ich_arg = vmbus_sc;
// 	config_intrhook_establish(&vmbus_sc->vmbus_intrhook);
// #else	/* !EARLY_AP_STARTUP */
// 	/* 
// 	 * If the system has already booted and thread
// 	 * scheduling is possible indicated by the global
// 	 * cold set to zero, we just call the driver
// 	 * initialization directly.
// 	 */
	// if (!cold)
		vmbus_doattach(vmbus_sc);
// #endif	/* EARLY_AP_STARTUP */

	return (0);
}

// static int
// vmbus_detach(device_t dev)
// {
// 	struct vmbus_softc *sc = device_get_softc(dev);

// 	bus_generic_detach(dev);
// 	vmbus_chan_destroy_all(sc);

// 	vmbus_scan_teardown(sc);

// 	vmbus_disconnect(sc);

// 	if (sc->vmbus_flags & VMBUS_FLAG_SYNIC) {
// 		sc->vmbus_flags &= ~VMBUS_FLAG_SYNIC;
// 		smp_rendezvous(NULL, vmbus_synic_teardown, NULL, NULL);
// 	}

// 	vmbus_intr_teardown(sc);
// 	vmbus_dma_free(sc);

// 	if (sc->vmbus_xc != NULL) {
// 		vmbus_xact_ctx_destroy(sc->vmbus_xc);
// 		sc->vmbus_xc = NULL;
// 	}

// 	free(__DEVOLATILE(void *, sc->vmbus_chmap), M_DEVBUF);
// 	mtx_destroy(&sc->vmbus_prichan_lock);
// 	mtx_destroy(&sc->vmbus_chan_lock);

// #ifdef NEW_PCIB
// 	vmbus_free_mmio_res(dev);
// #endif

// 	return (0);
// }

// #ifndef EARLY_AP_STARTUP

// static void
// vmbus_sysinit(void *arg __unused)
// {
	// struct vmbus_softc *sc = vmbus_get_softc();

	// if (vm_guest != VM_GUEST_HV || sc == NULL)
	// 	return;

	// /* 
	//  * If the system has already booted and thread
	//  * scheduling is possible, as indicated by the
	//  * global cold set to zero, we just call the driver
	//  * initialization directly.
	//  */
	// if (!cold) 
	// 	vmbus_doattach(sc);
// }
// /*
//  * NOTE:
//  * We have to start as the last step of SI_SUB_SMP, i.e. after SMP is
//  * initialized.
//  */
// SYSINIT(vmbus_initialize, SI_SUB_SMP, SI_ORDER_ANY, vmbus_sysinit, NULL);

// #endif	/* !EARLY_AP_STARTUP */

static struct uk_alloc *a;

/* Helper functions for vmbus related allocations */
struct uk_alloc * vmbus_get_alloc(void)
{
	return a;
}

/**
 *   Driver module local function(s).
 */
static int vmbus_device_reinit(struct vmbus_device *vdev);
static struct vmbus_driver *vmbus_find_driver(struct hyperv_guid *guid);
static int uk_vmbus_init(struct uk_alloc *a);
static int uk_vmbus_probe(void);

/**
 * Find a match driver
 * @param vdev
 *	Reference to the vmbus device.
 */
static struct vmbus_driver *vmbus_find_driver(struct hyperv_guid *guid)
{
	int i = 0;
	struct vmbus_driver *drv = NULL;

	UK_TAILQ_FOREACH(drv, &vbh.drv_list, next) {
		if (memcmp(guid, drv->guid, sizeof(struct hyperv_guid)) == 0) {
			return drv;
		}
	}
	return NULL;
}

/**
 * Reinitialize the vmbus device
 * @param vdev
 *	Reference to the vmbus device.
 */
static int vmbus_device_reinit(struct vmbus_device *vdev)
{
	int rc = 0;

	/**
	 * Resetting the vmbus device
	 * This may not be necessary while initializing the device for the first
	 * time.
	 */
	// if (vdev->cops->device_reset) {
	// 	vdev->cops->device_reset(vdev);
		/* Set the device status */
		vdev->status = VMBUS_DEV_RESET;
	// }
	/* Acknowledge the vmbus device */
	// rc = vmbus_dev_status_update(vdev, VMBUS_CONFIG_STATUS_ACK);
	if (rc != 0) {
		uk_pr_err("Failed to acknowledge the vmbus device %p: %d\n",
			  vdev, rc);
		return rc;
	}

	/* Acknowledge the vmbus driver */
	// rc = vmbus_dev_status_update(vdev, VMBUS_CONFIG_STATUS_DRIVER);
	if (rc != 0) {
		uk_pr_err("Failed to acknowledge the vmbus driver %p: %d\n",
			  vdev, rc);
		return rc;
	}
	vdev->status = VMBUS_DEV_INITIALIZED;
	uk_pr_info("vmbus device %p initialized\n", vdev);
	return rc;
}

#if 0
int vmbus_register_device(struct vmbus_device *vdev)
{
	struct vmbus_driver *drv = NULL;
	int rc = 0;

	UK_ASSERT(vdev);
	/* Check for the dev with the driver list */
	drv = vmbus_find_driver(vdev);
	if (!drv) {
		// uk_pr_err("Failed to find the driver for the vmbus device %p (id:%"__PRIu16")\n",
		// 	  vdev, vdev->id.vmbus_device_id);
		return -EFAULT;
	}
	vdev->vdrv = drv;

	/* Initialize the device */
	rc = vmbus_device_reinit(vdev);
	if (rc != 0) {
		// uk_pr_err("Failed to initialize the vmbus device %p (id:%"__PRIu16": %d\n",
		// 	  vdev, vdev->id.vmbus_device_id, rc);
		return rc;
	}

	// /* Initialize the virtqueue list */
	// UK_TAILQ_INIT(&vdev->vqs);

	/* Calling the driver add device */
	rc = drv->add_dev(vdev);
	if (rc != 0) {
		uk_pr_err("Failed to add the vmbus device %p: %d\n", vdev, rc);
		goto vmbus_dev_fail_set;
	}
exit:
	return rc;

vmbus_dev_fail_set:
	/**
	 * We set the status to fail. We can ignore the exit status from the
	 * status update.
	 */
	// vmbus_dev_status_update(vdev, VMBUS_CONFIG_STATUS_FAIL);
	goto exit;
}
#endif

static int vmbus_probe_device(struct vmbus_driver *drv,
		struct vmbus_channel *chan)
{
	int err;
	struct vmbus_device *dev;

	uk_pr_debug("[vmbus_probe_device] start\n");

	vmbus_sc->vmbus_probedone = true;

	dev = uk_calloc(vbh.a, 1, sizeof(*dev));
	if (!dev) {
		uk_pr_err("Failed to initialize: Out of memory!\n");
		err = -ENOMEM;
		return err;
	}
	dev->priv = chan;

	err = drv->add_dev(dev);
	if (err) {
		uk_pr_err("Failed to add device.\n");
		uk_free(vbh.a, dev);
	}

	uk_pr_debug("[vmbus_probe_device] end\n");
	return err;
}

static int vmbus_probe_device_type(struct vmbus_channel *chan)
{
	struct vmbus_driver *drv;
	char **devices = NULL;
	int err = 0;

	uk_pr_debug("[%s] start\n", __func__);

	drv = vmbus_find_driver(&chan->ch_guid_type);
	if (!drv) {
		uk_pr_warn("No driver for device type: %d\n", chan->ch_guid_inst.hv_guid[0]);
		atomic_subtract_int(&vmbus_sc->vmbus_scancount, 1);
		uk_pr_debug("[%s] no driver, vmbus_scancount decrement: %u\n", __func__, vmbus_sc->vmbus_scancount);
		wakeup(&vmbus_sc->vmbus_scandone_wq);
		return 0;
	}

	err = vmbus_probe_device(drv, chan);

	atomic_subtract_int(&vmbus_sc->vmbus_scancount, 1);
	uk_pr_debug("[%s] vmbus_scancount decrement: %u\n", __func__, vmbus_sc->vmbus_scancount);
	wakeup(&vmbus_sc->vmbus_scandone_wq);

	uk_pr_debug("[%s] end error: %d\n", __func__, err);
	return err;
}

/**
 * Probe for the vmbus device.
 */
static int uk_vmbus_probe(void)
{
	uk_pr_info("vmbus_probe start\n");

	vmbus_attach(vbh.a);

	uk_pr_info("vmbus_probe end\n");

	return 0;
}

/**
 * Initialize the Hyper-V vmbus driver(s).
 * @param a
 *	Reference to the memory allocator.
 * @return
 *	(int) On successful initialization return the count of device
 *	initialized.
 *	On error return -1.
 */
static int uk_vmbus_init(struct uk_alloc *a)
{
	struct vmbus_driver *drv = NULL, *ndrv = NULL;
	int ret = 0, dev_count = 0;

	uk_pr_info("uk_vmbus_init start\n");

	vbh.a = a;

	hyperv_init(NULL);

	UK_TAILQ_FOREACH_SAFE(drv, &vbh.drv_list, next, ndrv) {
		if (drv->init) {
			ret = drv->init(a);
			if (unlikely(ret)) {
				uk_pr_err("Failed to initialize vmbus driver %p: %d\n",
					  drv, ret);
				UK_TAILQ_REMOVE(&vbh.drv_list, drv, next);
			} else
				dev_count++;
		}
	}

	uk_pr_info("uk_vmbus_init end\n");

	return (dev_count > 0) ? dev_count : 0;
}

void _vmbus_register_driver(struct vmbus_driver *drv)
{
	UK_ASSERT(drv != NULL);
	uk_pr_info("[vmbus_register_driver] vmbus child driver registers\n");
	UK_TAILQ_INSERT_TAIL(&vbh.drv_list, drv, next);
}

static struct vmbus_handler vbh = {
	.b.init  = uk_vmbus_init,
	.b.probe = uk_vmbus_probe,
	.drv_list = UK_TAILQ_HEAD_INITIALIZER(vbh.drv_list),
};

UK_BUS_REGISTER(&vbh.b);
