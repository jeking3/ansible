#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2018, James E. King III (@jeking3) <jking@apache.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: vmware_guest_storage_controller
short_description: Manage storage controllers in a virtual machine
description:
    - This module can be used to add, remove and update storage
      controllers belonging to a given virtual machine.
    - All parameters and VMware object names are case sensitive.
    - This module is destructive in nature, please read documentation
      carefully before proceeding.
    - Be careful when removing disk controllers as this may lead to data loss.
version_added: 2.8
author:
    - James E. King III (@jeking3) <jking@apache.org>
notes:
    - Tested on vSphere 6.7
requirements:
    - "python >= 2.6"
    - PyVmomi
options:
   name:
     description:
     - Name of the virtual machine.
     - This is a required parameter, if parameter C(uuid) is not supplied.
   uuid:
     description:
     - UUID of the instance to gather facts if known, this is VMware's unique identifier.
     - This is a required parameter, if parameter C(name) is not supplied.
   folder:
     description:
     - Destination folder, absolute or relative path to find an existing guest.
     - This is a required parameter, only if multiple VMs are found with same name.
     - The folder should include the datacenter. ESX's datacenter is ha-datacenter
     - 'Examples:'
     - '   folder: /ha-datacenter/vm'
     - '   folder: ha-datacenter/vm'
     - '   folder: /datacenter1/vm'
     - '   folder: datacenter1/vm'
     - '   folder: /datacenter1/vm/folder1'
     - '   folder: datacenter1/vm/folder1'
     - '   folder: /folder1/datacenter1/vm'
     - '   folder: folder1/datacenter1/vm'
     - '   folder: /folder1/datacenter1/vm/folder2'
   datacenter:
     description:
     - The datacenter name to which virtual machine belongs to.
     required: True
     aliases: ['datacenter_name']
   controller:
     description:
     - A list of storage controllers to add, remove, or update.
     - All values and parameters are case sensitive.
     - 'Valid attributes are:'
     - ' - C(bus_number) (int): Specifies the bus number.  Required when C(state) is C(absent).'
     - '   If not specified when C(state) is C(present), a new controller will be created if possible.'
     - ' - C(state) (str): State of the controller.  The default state is C(present).
     - ' - If C(state) is set to C(absent), storage controller will be removed permanently from virtual machine configuration.'
     - '   This requires the storage controller to be empty.'
     - ' - If C(state) is set to C(present), storage controller will be added if not present at given bus number.'
     - ' - C(type) (str): Type of controller.  The type cannot be changed once created.  Valid values are:'
     - '   - C(buslogic): Virtual BusLogic SCSI Controller'
     - '   - C(ide): Virtual IDE Controller'
     - '   - C(lsisas): Virtual LSI SAS Controller'
     - '   - C(lsiscsi): Virtual LSI (Parallel) SCSI Controller'
     - '   - C(paravirtual): VMware Paravirtual SCSI Controller'
     - '   - C(sata): Virtual SATA Controller'
     - ' - C(shared) (str): Specifies sharing rules specific to SCSI controllers.  This option cannot be
     - '   changed when the virtual machine is running.  Valid values are:'
     - '   - C(noSharing): The virtual SCSI bus is not shared.  This is the default.'
     - '   - C(physicalSharing): The virtual SCSI bus is shared between two or more virtual machines'
     - '     residing on different physical hosts.'
     - '   - C(virtualSharing): The virtual SCSI bus is shared between two or more virtual machines'
     - '     running on the same ESXi Host.'
extends_documentation_fragment: vmware.documentation
'''

EXAMPLES = '''
TODO
- name: Add disks to virtual machine using UUID
  vmware_guest_disk:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    validate_certs: no
    uuid: 421e4592-c069-924d-ce20-7e7533fab926
    disk:
      - size_mb: 10
        type: thin
        datastore: datacluster0
        state: present
        scsi_controller: 1
        unit_number: 1
        scsi_type: 'paravirtual'
      - size_gb: 10
        type: eagerzeroedthick
        state: present
        autoselect_datastore: True
        scsi_controller: 2
        scsi_type: 'buslogic'
        unit_number: 12
      - size: 10Gb
        type: eagerzeroedthick
        state: present
        autoselect_datastore: True
        scsi_controller: 2
        scsi_type: 'buslogic'
        unit_number: 1
  delegate_to: localhost
  register: disk_facts

- name: Remove disks from virtual machine using name
  vmware_guest_disk:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    validate_certs: no
    name: VM_225
    disk:
      - state: absent
        scsi_controller: 1
        unit_number: 1
  delegate_to: localhost
  register: disk_facts
'''

RETURN = """
TODO:
disk_status:
    description: metadata about the virtual machine's disks after managing them
    returned: always
    type: dict
    sample: {
        "0": {
            "backing_datastore": "datastore2",
            "backing_disk_mode": "persistent",
            "backing_eagerlyscrub": false,
            "backing_filename": "[datastore2] VM_225/VM_225.vmdk",
            "backing_thinprovisioned": false,
            "backing_writethrough": false,
            "capacity_in_bytes": 10485760,
            "capacity_in_kb": 10240,
            "controller_key": 1000,
            "key": 2000,
            "label": "Hard disk 1",
            "summary": "10,240 KB",
            "unit_number": 0
        },
    }
"""

import re
try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.vmware import PyVmomi, vmware_argument_spec, wait_for_task, find_obj, get_all_objs


class PyVmomiHelper(PyVmomi):
    def __init__(self, module):
        super(PyVmomiHelper, self).__init__(module)
        self.controllers = self.params['controller']
        self.vm = None
        self.controller_types = dict(lsiscsi=vim.vm.device.VirtualLsiLogicController,
                                     paravirtual=vim.vm.device.ParaVirtualSCSIController,
                                     buslogic=vim.vm.device.VirtualBusLogicController,
                                     lsisas=vim.vm.device.VirtualLsiLogicSASController,
                                     ide=vim.vm.device.VirtualIDEController,
                                     sata=vim.vm.defice.VirtualSATAController)
        self.config_spec = vim.vm.ConfigSpec()
        self.config_spec.deviceChange = []

    def create_scsi_controller(self, scsi_type, scsi_bus_number):
        """
        Create SCSI Controller with given SCSI Type and SCSI Bus Number
        Args:
            scsi_type: Type of SCSI
            scsi_bus_number: SCSI Bus number to be assigned

        Returns: Virtual device spec for SCSI Controller

        """
        scsi_ctl = vim.vm.device.VirtualDeviceSpec()
        scsi_ctl.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        scsi_ctl.device = self.scsi_device_type[scsi_type]()
        scsi_ctl.device.unitNumber = 3
        scsi_ctl.device.busNumber = scsi_bus_number
        scsi_ctl.device.hotAddRemove = True
        scsi_ctl.device.sharedBus = 'noSharing'
        scsi_ctl.device.scsiCtlrUnitNumber = 7

        return scsi_ctl

    @staticmethod
    def create_scsi_disk(scsi_ctl_key, disk_index):
        """
        Create Virtual Device Spec for virtual disk
        Args:
            scsi_ctl_key: Unique SCSI Controller Key
            disk_index: Disk unit number at which disk needs to be attached

        Returns: Virtual Device Spec for virtual disk

        """
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        disk_spec.device.backing.diskMode = 'persistent'
        disk_spec.device.controllerKey = scsi_ctl_key
        disk_spec.device.unitNumber = disk_index
        return disk_spec

    def reconfigure_vm(self, config_spec, device_type):
        """
        Reconfigure virtual machine after modifying device spec
        Args:
            config_spec: Config Spec
            device_type: Type of device being modified

        Returns: Boolean status 'changed' and actual task result

        """
        changed, results = (False, '')
        try:
            # Perform actual VM reconfiguration
            task = self.vm.ReconfigVM_Task(spec=config_spec)
            changed, results = wait_for_task(task)
        except vim.fault.InvalidDeviceSpec as invalid_device_spec:
            self.module.fail_json(msg="Failed to manage %s on given virtual machine due to invalid"
                                      " device spec : %s" % (device_type, to_native(invalid_device_spec.msg)),
                                  details="Please check ESXi server logs for more details.")
        except vim.fault.RestrictedVersion as e:
            self.module.fail_json(msg="Failed to reconfigure virtual machine due to"
                                      " product versioning restrictions: %s" % to_native(e.msg))

        return changed, results

    def ensure_controllers(self, vm_obj=None):
        """
        Manage internal state of virtual machine controllers
        Args:
            vm_obj: Managed object of virtual machine
        """
        # Set vm object
        self.vm = vm_obj
        # Sanitize user input
        disk_data = self.sanitize_disk_inputs()
        # Create stateful information about SCSI devices
        current_scsi_info = dict()
        results = dict(changed=False, disk_data=None, disk_changes=dict())

        # Deal with SCSI Controller
        for device in vm_obj.config.hardware.device:
            if isinstance(device, tuple(self.scsi_device_type.values())):
                # Found SCSI device
                if device.busNumber not in current_scsi_info:
                    device_bus_number = 1000 + device.busNumber
                    current_scsi_info[device_bus_number] = dict(disks=dict())

        scsi_changed = False
        for disk in disk_data:
            scsi_controller = disk['scsi_controller'] + 1000
            if scsi_controller not in current_scsi_info and disk['state'] == 'present':
                scsi_ctl = self.create_scsi_controller(disk['scsi_type'], disk['scsi_controller'])
                current_scsi_info[scsi_controller] = dict(disks=dict())
                self.config_spec.deviceChange.append(scsi_ctl)
                scsi_changed = True
        if scsi_changed:
            self.reconfigure_vm(self.config_spec, 'SCSI Controller')
            self.config_spec = vim.vm.ConfigSpec()
            self.config_spec.deviceChange = []

        # Deal with Disks
        for device in vm_obj.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualDisk):
                # Found Virtual Disk device
                if device.controllerKey not in current_scsi_info:
                    current_scsi_info[device.controllerKey] = dict(disks=dict())
                current_scsi_info[device.controllerKey]['disks'][device.unitNumber] = device

        vm_name = self.vm.name
        disk_change_list = []
        for disk in disk_data:
            disk_change = False
            scsi_controller = disk['scsi_controller'] + 1000  # VMware auto assign 1000 + SCSI Controller
            if disk['disk_unit_number'] not in current_scsi_info[scsi_controller]['disks'] and disk['state'] == 'present':
                # Add new disk
                disk_spec = self.create_scsi_disk(scsi_controller, disk['disk_unit_number'])
                disk_spec.device.capacityInKB = disk['size']
                if disk['disk_type'] == 'thin':
                    disk_spec.device.backing.thinProvisioned = True
                elif disk['disk_type'] == 'eagerzeroedthick':
                    disk_spec.device.backing.eagerlyScrub = True
                disk_spec.device.backing.fileName = "[%s] %s/%s_%s_%s.vmdk" % (disk['datastore'].name,
                                                                               vm_name, vm_name,
                                                                               str(scsi_controller),
                                                                               str(disk['disk_unit_number']))
                disk_spec.device.backing.datastore = disk['datastore']
                self.config_spec.deviceChange.append(disk_spec)
                disk_change = True
                current_scsi_info[scsi_controller]['disks'][disk['disk_unit_number']] = disk_spec.device
                results['disk_changes'][disk['disk_index']] = "Disk created."
            elif disk['disk_unit_number'] in current_scsi_info[scsi_controller]['disks']:
                if disk['state'] == 'present':
                    disk_spec = vim.vm.device.VirtualDeviceSpec()
                    # set the operation to edit so that it knows to keep other settings
                    disk_spec.device = current_scsi_info[scsi_controller]['disks'][disk['disk_unit_number']]
                    # Edit and no resizing allowed
                    if disk['size'] < disk_spec.device.capacityInKB:
                        self.module.fail_json(msg="Given disk size at disk index [%s] is smaller than found (%d < %d)."
                                                  " Reducing disks is not allowed." % (disk['disk_index'],
                                                                                       disk['size'],
                                                                                       disk_spec.device.capacityInKB))
                    if disk['size'] != disk_spec.device.capacityInKB:
                        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
                        disk_spec.device.capacityInKB = disk['size']
                        self.config_spec.deviceChange.append(disk_spec)
                        disk_change = True
                        results['disk_changes'][disk['disk_index']] = "Disk size increased."
                    else:
                        results['disk_changes'][disk['disk_index']] = "Disk already exists."

                elif disk['state'] == 'absent':
                    # Disk already exists, deleting
                    disk_spec = vim.vm.device.VirtualDeviceSpec()
                    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
                    disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.destroy
                    disk_spec.device = current_scsi_info[scsi_controller]['disks'][disk['disk_unit_number']]
                    self.config_spec.deviceChange.append(disk_spec)
                    disk_change = True
                    results['disk_changes'][disk['disk_index']] = "Disk deleted."

            if disk_change:
                # Adding multiple disks in a single attempt raises weird errors
                # So adding single disk at a time.
                self.reconfigure_vm(self.config_spec, 'disks')
                self.config_spec = vim.vm.ConfigSpec()
                self.config_spec.deviceChange = []
            disk_change_list.append(disk_change)

        if any(disk_change_list):
            results['changed'] = True
        results['disk_data'] = self.gather_disk_facts(vm_obj=self.vm)
        self.module.exit_json(**results)

    def sanitize_controller_inputs(self):
        """
        Check correctness of controller input provided by user
        Returns: A list of dictionary containing controller information
        """
        controller_data = list()
        if not self.controllers:
            self.module.exit_json(changed=False, msg="No controllers provided for virtual"
                                                     " machine '%s' for management." % self.vm.name)

        for controller_index, controller in enumerate(self.controllers):
            # Check state
            if 'state' not in controller:
                if controller['state'] not in ['absent', 'present']:
                    self.module.fail_json(msg="Invalid state provided '%s' for disk index [%s]."
                                              " State can be either - 'absent', 'present'" % (disk['state'],
                                                                                              disk_index))
                else:
                    current_disk['state'] = disk['state']

            if current_disk['state'] == 'present':
                # Select datastore or datastore cluster
                if 'datastore' in disk:
                    if 'autoselect_datastore' in disk:
                        self.module.fail_json(msg="Please specify either 'datastore' "
                                                  "or 'autoselect_datastore' for disk index [%s]" % disk_index)

                    # Check if given value is datastore or datastore cluster
                    datastore_name = disk['datastore']
                    datastore_cluster = find_obj(self.content, [vim.StoragePod], datastore_name)
                    if datastore_cluster:
                        # If user specified datastore cluster so get recommended datastore
                        datastore_name = self.get_recommended_datastore(datastore_cluster_obj=datastore_cluster)
                    # Check if get_recommended_datastore or user specified datastore exists or not
                    datastore = find_obj(self.content, [vim.Datastore], datastore_name)
                    if datastore is None:
                        self.module.fail_json(msg="Failed to find datastore named '%s' "
                                                  "in given configuration." % disk['datastore'])
                    current_disk['datastore'] = datastore
                    current_disk['autoselect_datastore'] = False
                elif 'autoselect_datastore' in disk:
                    # Find datastore which fits requirement
                    datastores = get_all_objs(self.content, [vim.Datastore])
                    if not datastores:
                        self.module.fail_json(msg="Failed to gather information about"
                                                  " available datastores in given datacenter.")
                    datastore = None
                    datastore_freespace = 0
                    for ds in datastores:
                        if ds.summary.freeSpace > datastore_freespace:
                            # If datastore field is provided, filter destination datastores
                            datastore = ds
                            datastore_freespace = ds.summary.freeSpace
                    current_disk['datastore'] = datastore

                if 'datastore' not in disk and 'autoselect_datastore' not in disk:
                    self.module.fail_json(msg="Either 'datastore' or 'autoselect_datastore' is"
                                              " required parameter while creating disk for "
                                              "disk index [%s]." % disk_index)

                if [x for x in disk.keys() if x.startswith('size_') or x == 'size']:
                    # size, size_tb, size_gb, size_mb, size_kb
                    disk_size_parse_failed = False
                    if 'size' in disk:
                        size_regex = re.compile(r'(\d+(?:\.\d+)?)([tgmkTGMK][bB])')
                        disk_size_m = size_regex.match(disk['size'])
                        if disk_size_m:
                            expected = disk_size_m.group(1)
                            unit = disk_size_m.group(2)
                        else:
                            disk_size_parse_failed = True
                        try:
                            if re.match(r'\d+\.\d+', expected):
                                # We found float value in string, let's typecast it
                                expected = float(expected)
                            else:
                                # We found int value in string, let's typecast it
                                expected = int(expected)
                        except (TypeError, ValueError, NameError):
                            disk_size_parse_failed = True
                    else:
                        # Even multiple size_ parameter provided by user,
                        # consider first value only
                        param = [x for x in disk.keys() if x.startswith('size_')][0]
                        unit = param.split('_')[-1]
                        disk_size = disk[param]
                        if isinstance(disk_size, (float, int)):
                            disk_size = str(disk_size)

                        try:
                            if re.match(r'\d+\.\d+', disk_size):
                                # We found float value in string, let's typecast it
                                expected = float(disk_size)
                            else:
                                # We found int value in string, let's typecast it
                                expected = int(disk_size)
                        except (TypeError, ValueError, NameError):
                            disk_size_parse_failed = True

                    if disk_size_parse_failed:
                        # Common failure
                        self.module.fail_json(msg="Failed to parse disk size for disk index [%s],"
                                                  " please review value provided"
                                                  " using documentation." % disk_index)

                    disk_units = dict(tb=3, gb=2, mb=1, kb=0)
                    unit = unit.lower()
                    if unit in disk_units:
                        current_disk['size'] = expected * (1024 ** disk_units[unit])
                    else:
                        self.module.fail_json(msg="%s is not a supported unit for disk size for disk index [%s]."
                                                  " Supported units are ['%s']." % (unit,
                                                                                    disk_index,
                                                                                    "', '".join(disk_units.keys())))

                else:
                    # No size found but disk, fail
                    self.module.fail_json(msg="No size, size_kb, size_mb, size_gb or size_tb"
                                              " attribute found into disk index [%s] configuration." % disk_index)
            # Check SCSI controller key
            if 'scsi_controller' in disk:
                try:
                    temp_disk_controller = int(disk['scsi_controller'])
                except ValueError:
                    self.module.fail_json(msg="Invalid SCSI controller ID '%s' specified"
                                              " at index [%s]" % (disk['scsi_controller'], disk_index))
                if temp_disk_controller not in range(0, 4):
                    # Only 4 SCSI controllers are allowed per VM
                    self.module.fail_json(msg="Invalid SCSI controller ID specified [%s],"
                                              " please specify value between 0 to 3 only." % temp_disk_controller)
                current_disk['scsi_controller'] = temp_disk_controller
            else:
                self.module.fail_json(msg="Please specify 'scsi_controller' under disk parameter"
                                          " at index [%s], which is required while creating disk." % disk_index)
            # Check for disk unit number
            if 'unit_number' in disk:
                try:
                    temp_disk_unit_number = int(disk['unit_number'])
                except ValueError:
                    self.module.fail_json(msg="Invalid Disk unit number ID '%s'"
                                              " specified at index [%s]" % (disk['unit_number'], disk_index))
                if temp_disk_unit_number not in range(0, 16):
                    self.module.fail_json(msg="Invalid Disk unit number ID specified for disk [%s] at index [%s],"
                                              " please specify value between 0 to 15"
                                              " only (excluding 7)." % (temp_disk_unit_number, disk_index))

                if temp_disk_unit_number == 7:
                    self.module.fail_json(msg="Invalid Disk unit number ID specified for disk at index [%s],"
                                              " please specify value other than 7 as it is reserved"
                                              "for SCSI Controller" % disk_index)
                current_disk['disk_unit_number'] = temp_disk_unit_number

            else:
                self.module.fail_json(msg="Please specify 'unit_number' under disk parameter"
                                          " at index [%s], which is required while creating disk." % disk_index)

            # Type of Disk
            disk_type = disk.get('type', 'thick').lower()
            if disk_type not in ['thin', 'thick', 'eagerzeroedthick']:
                self.module.fail_json(msg="Invalid 'disk_type' specified for disk index [%s]. Please specify"
                                          " 'disk_type' value from ['thin', 'thick', 'eagerzeroedthick']." % disk_index)
            current_disk['disk_type'] = disk_type

            # SCSI Controller Type
            scsi_contrl_type = disk.get('scsi_type', 'paravirtual').lower()
            if scsi_contrl_type not in self.scsi_device_type.keys():
                self.module.fail_json(msg="Invalid 'scsi_type' specified for disk index [%s]. Please specify"
                                          " 'scsi_type' value from ['%s']" % (disk_index,
                                                                              "', '".join(self.scsi_device_type.keys())))
            current_disk['scsi_type'] = scsi_contrl_type

            disks_data.append(current_disk)
        return disks_data

    def get_recommended_datastore(self, datastore_cluster_obj):
        """
        Return Storage DRS recommended datastore from datastore cluster
        Args:
            datastore_cluster_obj: datastore cluster managed object

        Returns: Name of recommended datastore from the given datastore cluster,
                 Returns None if no datastore recommendation found.

        """
        # Check if Datastore Cluster provided by user is SDRS ready
        sdrs_status = datastore_cluster_obj.podStorageDrsEntry.storageDrsConfig.podConfig.enabled
        if sdrs_status:
            # We can get storage recommendation only if SDRS is enabled on given datastorage cluster
            pod_sel_spec = vim.storageDrs.PodSelectionSpec()
            pod_sel_spec.storagePod = datastore_cluster_obj
            storage_spec = vim.storageDrs.StoragePlacementSpec()
            storage_spec.podSelectionSpec = pod_sel_spec
            storage_spec.type = 'create'

            try:
                rec = self.content.storageResourceManager.RecommendDatastores(storageSpec=storage_spec)
                rec_action = rec.recommendations[0].action[0]
                return rec_action.destination.name
            except Exception as e:
                # There is some error so we fall back to general workflow
                pass
        datastore = None
        datastore_freespace = 0
        for ds in datastore_cluster_obj.childEntity:
            if ds.summary.freeSpace > datastore_freespace:
                # If datastore field is provided, filter destination datastores
                datastore = ds
                datastore_freespace = ds.summary.freeSpace
        if datastore:
            return datastore.name
        return None

    @staticmethod
    def gather_disk_facts(vm_obj):
        """
        Gather facts about VM's disks
        Args:
            vm_obj: Managed object of virtual machine

        Returns: A list of dict containing disks information

        """
        disks_facts = dict()
        if vm_obj is None:
            return disks_facts

        disk_index = 0
        for disk in vm_obj.config.hardware.device:
            if isinstance(disk, vim.vm.device.VirtualDisk):
                disks_facts[disk_index] = dict(
                    key=disk.key,
                    label=disk.deviceInfo.label,
                    summary=disk.deviceInfo.summary,
                    backing_filename=disk.backing.fileName,
                    backing_datastore=disk.backing.datastore.name,
                    backing_disk_mode=disk.backing.diskMode,
                    backing_writethrough=disk.backing.writeThrough,
                    backing_thinprovisioned=disk.backing.thinProvisioned,
                    backing_eagerlyscrub=bool(disk.backing.eagerlyScrub),
                    controller_key=disk.controllerKey,
                    unit_number=disk.unitNumber,
                    capacity_in_kb=disk.capacityInKB,
                    capacity_in_bytes=disk.capacityInBytes,
                )
                disk_index += 1
        return disks_facts


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(
        name=dict(type='str'),
        uuid=dict(type='str'),
        folder=dict(type='str'),
        datacenter=dict(type='str', required=True),
        controller=dict(type=list, default=[]),
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=[['name', 'uuid']])

    if module.params['folder']:
        # FindByInventoryPath() does not require an absolute path
        # so we should leave the input folder path unmodified
        module.params['folder'] = module.params['folder'].rstrip('/')

    pyv = PyVmomiHelper(module)
    # Check if the VM exists before continuing
    vm = pyv.get_vm()

    if not vm:
        # We unable to find the virtual machine user specified
        # Bail out
        module.fail_json(msg="Cannot find virtual machine '%s'."
                             .format(module.params.get('uuid') or module.params.get('name')))
        

    # VM exists
    try:
        pyv.ensure_controllers(vm_obj=vm)
    except Exception as exc:
        module.fail_json(msg="Failed to manage controllers for virtual machine"
                             " '%s' with exception : %s" % (vm.name,
                                                            to_native(exc)))


if __name__ == '__main__':
    main()
