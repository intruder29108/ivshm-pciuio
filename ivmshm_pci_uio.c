/*
 * UIO driver for QEMU IVMSHM PCI device.
 *
 */
#include <linux/device.h>
#include <linux/module.h>
#include <linux/eventfd.h>
#include <linux/irq.h>
#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/uio_driver.h>
#include <linux/eventfd.h>
#include <uapi/linux/limits.h>

#include "../irq-eventfd/irq_eventfd.h"

#define PCI_IVMSHM_VID		(0x1af4)
#define PCI_IVMSHM_DID		(0x1110)
#define PCI_IVMSHM_NUM_BARS	(3)

#define ivmshm_dbg(dev, fmt, ...)					\
do {									\
	if(dev->verbose) {						\
		pci_info(dev->pdev, "[INFO]: "fmt"\n", ##__VA_ARGS__);	\
	}								\
} while(0)

struct ivmshm_intr_info {
	struct pci_dev *dev;
	int vector;
	int irq;
	char name[NAME_MAX];
};

struct ivmshm_pcidev_info {
	struct pci_dev *pdev;
	struct uio_info uinfo;
	int nmsi_vecs;
	struct ivmshm_intr_info *intr_info;
	struct irqefd_devdata efd_devdata;
	bool verbose;
};

/*
 * Module load parameters.
 */
static bool debug = false;
module_param(debug, bool, 0);

static irqreturn_t ivmshm_intr_handler(int irq, void *arg) {

	struct ivmshm_intr_info *intr_info = (struct ivmshm_intr_info *)arg;
	struct ivmshm_pcidev_info *dev =  pci_get_drvdata(intr_info->dev);
	struct irqefd_devdata *efd_devdata = &dev->efd_devdata;

	ivmshm_dbg(dev, "interrupt(\"%s\") vector(%d) irq(%d)",
			intr_info->name, intr_info->vector, intr_info->irq);
	if (efd_devdata->ctx && efd_devdata->ctx[intr_info->vector]) {
		if (eventfd_signal(efd_devdata->ctx[intr_info->vector], 1) < 1) {
			pci_err(intr_info->dev, "[ERR]: failed to signal event"
					" for vector(%d)\n", intr_info->vector);
		} else {
			ivmshm_dbg(dev, "signaled event(0x%p) with value(1)",
					efd_devdata->ctx[intr_info->vector]);
		}
	}

	return IRQ_HANDLED;
}

static int ivmshm_pci_open(struct uio_info *info, struct inode *inode) {

	struct ivmshm_pcidev_info *dev =\
		container_of(info, typeof(*dev), uinfo);

	ivmshm_dbg(dev, "ivmshm_dev(%p) inode(%p)\n", dev, inode);
	dev->efd_devdata.inode = inode;

	return 0;
}

static int ivmshm_pci_release(struct uio_info *info, struct inode *inode) {

	struct ivmshm_pcidev_info *dev =\
		container_of(info, typeof(*dev), uinfo);

	ivmshm_dbg(dev, "ivmshm_dev(%p) inode(%p)\n", dev, inode);
	dev->efd_devdata.inode = NULL;

	return 0;
}

static int ivmshm_pci_probe(struct pci_dev *dev,
		const struct pci_device_id *id) {

	int ret = 0;
	struct ivmshm_pcidev_info *info;
	int i, j;
	int nmsi_vecs, irq;

	info = kzalloc(sizeof *info, GFP_KERNEL);
	if (!info) {
		pci_err(dev, "[ERR]: failed to allocate memory for devinfo");
		return -ENOMEM;
	}

	info->pdev = dev;
	info->verbose = debug;
	pci_set_drvdata(dev, info);
	ivmshm_dbg(info, "dev_info allocated(0x%p)", info);

	if ((ret = pci_enable_device(dev))) {
		goto fail_pci_enable_device;
	}
	ivmshm_dbg(info, "enabled pci device");

	pci_set_master(dev);
	ivmshm_dbg(info, "enabled bus mastering");

	if ((ret = pci_request_regions(dev, "ivmshm_pci_driver"))) {
		goto fail_pci_request_region;
	}

	for (i = 0; i < PCI_IVMSHM_NUM_BARS; i++) {
		info->uinfo.mem[i].addr = pci_resource_start(dev, i);
		if (!info->uinfo.mem[i].addr) {
			ret = -1;
			goto fail_pci_bar_scan;
		}
		info->uinfo.mem[i].internal_addr = pci_ioremap_bar(dev, i);
		if (!info->uinfo.mem[i].internal_addr) {
			ret = -1;
			goto fail_pci_bar_ioremap;
		}
		info->uinfo.mem[i].size = pci_resource_len(dev, i);
		info->uinfo.mem[i].memtype = UIO_MEM_PHYS;
		ivmshm_dbg(info, "bar(%d) phy_addr=0x%llx kvaddr=0x%p",
				i, info->uinfo.mem[i].addr,
				info->uinfo.mem[i].internal_addr);
	}
	info->uinfo.name = "ivmshm_pci";
	info->uinfo.version = "0.0.0";
	info->uinfo.open = ivmshm_pci_open;
	info->uinfo.release = ivmshm_pci_release;
	info->uinfo.irq = UIO_IRQ_NONE;
	info->uinfo.irq_flags = 0;

	if ((ret = uio_register_device(&dev->dev, &info->uinfo))) {
		pci_err(dev, "[ERR]: uio register device failed");
		goto fail_uio_register_device;
	}
	ivmshm_dbg(info, "device registered with uio driver");

	/*
	 * configure MSI-X interrupts.
	 */
	if (!pci_msi_enabled()) {
		ret = -1;
		pci_err(dev, "[ERR]: msi disabled in kernel");
		goto fail_msi_enable;
	}
	nmsi_vecs = pci_msix_vec_count(dev);
	if (nmsi_vecs < 0) {
		ret = -1;
		pci_err(dev, "[ERR]: device doesn't support MSI-X");
		goto fail_msix_support;
	}
	info->intr_info = kzalloc(sizeof(struct ivmshm_intr_info) * nmsi_vecs,
			GFP_KERNEL);
	if (!info->intr_info) {
		pci_err(dev, "[ERR]: failed to allocate intr_info");
		ret = -ENOMEM;
		goto fail_alloc_intr_info;
	}
	ivmshm_dbg(info, "device supports (%d) MSI-X vectors", nmsi_vecs);
	ret = pci_alloc_irq_vectors(dev, 1, nmsi_vecs, PCI_IRQ_MSIX);
	if (ret < nmsi_vecs) {
		pci_err(dev, "[ERR]: failed to allocate MSI-X vectors");
		if (ret > 0) {
			ret = -1;
			pci_free_irq_vectors(dev);
			goto fail_msix_allocate;
		}
	}
	info->nmsi_vecs = nmsi_vecs;
	ivmshm_dbg(info, "allocated (%d) MSI-X vectors", nmsi_vecs);
	for (j = 0; j < nmsi_vecs; j++) {
		irq = pci_irq_vector(dev, j);

		/*
		 * Populate interrupt information.
		 */
		info->intr_info[j].dev = dev;
		info->intr_info[j].vector = j;
		info->intr_info[j].irq = irq;
		sprintf(info->intr_info[j].name, "ivmshm_vector%d", j);
		ret = request_irq(irq, ivmshm_intr_handler, 0,
				info->intr_info[j].name, &info->intr_info[j]);
		if (ret) {
			ret = -1;
			pci_err(dev, "[ERR]: failed to request irq(%d)", irq);
			goto fail_request_irq;
		}
	}
	info->efd_devdata.num_events = nmsi_vecs;
	if (irqefd_register_device(&info->efd_devdata) != 0) {
		pci_err(dev, "[ERR]: failed to register device with"\
				" irqefd\n");
		ret = -1;
		goto fail_irqefd;
	}
	return 0;

fail_irqefd:
fail_request_irq:
	while (--j >= 0) {
		free_irq(info->intr_info[j].irq, &info->intr_info[j]);
	}
	pci_free_irq_vectors(dev);
fail_msix_allocate:
	kfree(info->intr_info);
fail_alloc_intr_info:
fail_msix_support:
fail_msi_enable:
	uio_unregister_device(&info->uinfo);
fail_uio_register_device:
fail_pci_bar_ioremap:
	while(--i >= 0) {
		iounmap(info->uinfo.mem[i].internal_addr);
	}
fail_pci_bar_scan:
	pci_release_regions(dev);
fail_pci_request_region:
	pci_disable_device(dev);
fail_pci_enable_device:
	kfree(info);
	return ret;
}

static void ivshm_pci_remove(struct pci_dev *dev) {

	struct ivmshm_pcidev_info *info = pci_get_drvdata(dev);
	int i;

	irqefd_unregister_device(&info->efd_devdata);
	for (i = 0; i< info->nmsi_vecs; i++) {
		free_irq(info->intr_info[i].irq, &info->intr_info[i]);
	}
	kfree(info->intr_info);
	pci_free_irq_vectors(dev);
	uio_unregister_device(&info->uinfo);
	for (i = 0; i < PCI_IVMSHM_NUM_BARS; i++) {
		iounmap(info->uinfo.mem[i].internal_addr);
	}
	pci_release_regions(dev);
	pci_disable_device(dev);
	kfree(info);
}


static struct pci_device_id ivmshm_pci_ids[] = {
	{
		PCI_DEVICE(PCI_IVMSHM_VID, PCI_IVMSHM_DID),
	},
	{0, } // null entry
};

static struct pci_driver ivmshm_pci_driver = {
	.name = "ivmshm_pci_driver",
	.id_table = ivmshm_pci_ids,
	.probe = ivmshm_pci_probe,
	.remove = ivshm_pci_remove,
};

module_pci_driver(ivmshm_pci_driver);
MODULE_DEVICE_TABLE(pci, ivmshm_pci_ids);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Antony Clince Alex");
