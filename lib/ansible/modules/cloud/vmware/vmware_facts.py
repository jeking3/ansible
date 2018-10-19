#!/usr/bin/python
# -*- coding: utf-8 -*-
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
module: vmware_facts
short_description: Collect facts from any vSphere inventory object.
description:
    - The property collector is an efficient way to extract properties
      from one or more (or all) objects.
    - The results are a direct translation of the vSphere API, which
      is a well documented and stable object hierarchy.
author:
    - "James E. King III (@jeking3) <jking@apache.org>"
version_added: 2.8
notes:
    - Tested on vSphere 6.7
requirements:
    - python >= 2.6
    - PyVmomi
options:
  type:
    description:
      - The type of object being looked up.
    choices:
      - ComputeResource
      - Datacenter
      - Datastore
      - Folder
      - HostSystem
      - ManagedEntity
      - Network
      - ResourcePool
      - VirtualMachine
    required: yes
  ids:
    description:
      - MOID(s) of objects to scope the request - these can be
        retrieved using the vmware_resolve action.
      - This is a very efficient way to get object information.
      - Example MOIDs: 'host-12', or 'vm-5432'
    type: list
    required: no
  properties:
    description:
      - Property name(s) to retrieve.  If not specified, all properties
        are retrieved.
      - Property names may use dotted notation to dig into structures.
      - Property names may not use array notation.
      - 'Examples:'
      - '   property:'
      - '     - config.hardware.memoryMB'
      - '     - guest.disk'
      - '     - runtime.powerState'
    type: list
    required: no
extends_documentation_fragment: vmware.documentation
'''

EXAMPLES = '''
- name: Query all datastores for their name, status, and vital space information.
  vmware_facts:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    type: 'Datastore'
    properties:
      - 'info'
      - 'name'
      - 'overallStatus'

- name: Query a few specific virtual machines for name, power state, status.
  vmware_facts:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    type: 'VirtualMachine'
    ids:
      - 'vm-123'
      - 'vm-456'
    properties:
      - 'name'
      - 'overallStatus'
      - 'runtime.powerState'
'''

RETURN = '''
results:
    description: result of the operation
    returned: always
    type: dict
    sample: { 
...
}
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import PyVmomi, vmware_argument_spec


class VmwareFacts(PyVmomi):
    def __init__(self, module):
        ''' Prepares for the upload. '''
        super(VmwareFacts, self).__init__(module)

    @property
    def ids(self):
        ''' Returns the IDS to filter on, if any. '''
        return self.module.params['ids']

    @property
    def names(self):
        ''' Returns the names to filter on, if any. '''
        return self.module.params['names']

    @property
    def properties(self):
        ''' Returns the properties to restrict results to, if any. '''
        return self.module.params['properties']

    @property
    def vimtype(self):
        ''' Returns a class template for the given type. '''
        return self.vimtype(self.module.params['type'])

    def collect(self):
        """
        Leverage the Property Collector to retrieve properties from any
        Managed Object.

        Args:
        - content: service instance content
        - type: object type
        - properties: optional array of properties to get (default: all)
        - ids: optional array of MOIDs to limit results (default: all)

        Returns:
        - dict: key = moid, value = dict of properties
        """

        rawdata = self.collect(type=self.vimtype, ids=self.ids, names=self.names,
            properties=self.properties)
        rootFolder = self.content.rootFolder
        viewMgr = content.viewManager
        if not ids:
            view = viewMgr.CreateContainerView(container=rootFolder,
                                               type=[vimtype],
                                               recursive=True)
        else:
            view = viewMgr.CreateListView()
            for id in ids:
                view.ModifyListView(add=[
                    pyVmomi.VmomiSupport.GetWsdlType('urn:vim25', type)(id)])

        traversal_spec = vmodl.query.PropertyCollector.TraversalSpec()
        traversal_spec.name = 'traverseEntities'
        traversal_spec.path = 'view'
        traversal_spec.skip = False
        traversal_spec.type = view.__class__

        obj_spec = vmodl.query.PropertyCollector.ObjectSpec()
        obj_spec.obj = view
        obj_spec.skip = True
        obj_spec.selectSet = [traversal_spec]

        property_spec = vmodl.query.PropertyCollector.PropertySpec()
        property_spec.type = vimtype
        if not properties:
            property_spec.all = True
        else:
            property_spec.pathSet = properties

        filter_spec = vmodl.query.PropertyCollector.FilterSpec()
        filter_spec.objectSet = [obj_spec]
        filter_spec.propSet = [property_spec]

        rawdata = content.propertyCollector.RetrieveContents([filter_spec])
        return self.transform(ids, rawdata) if not raw else rawdata

    def jsonify_vsphere_obj(self, obj):
        """JSONify a vSphere Managed/Data object."""
        class PyVmomiObjectJSONEncoder(json.JSONEncoder):
            """Custom JSON encoder to encode vSphere object."""
            def __init__(self, *args, **kwargs):
                super(PyVmomiObjectJSONEncoder, self).__init__(*args, **kwargs)

            def default(self, obj):  # pylint: disable=method-hidden
                if isinstance(obj, datetime.datetime):
                    return pyVmomi.Iso8601.ISO8601Format(obj)
                elif isinstance(obj, pyVmomi.VmomiSupport.DataObject):
                    # eliminate the very annoying Dynamic fields if empty
                    # if (obj.__dict__['dynamicType'] is None and
                    #         len(obj.__dict__['dynamicProperty']) == 0):
                    #     tmp = copy.deepcopy(obj.__dict__)
                    #     tmp.pop('dynamicType')
                    #     tmp.pop('dynamicProperty')
                    #     return tmp
                    return obj.__dict__
                elif isinstance(obj, pyVmomi.VmomiSupport.ManagedObject):
                    return unquote(obj).split(':')[-1]
                elif isinstance(obj, type):
                    return str(obj)
                return json.JSONEncoder.default(self, obj)
        return json.loads(PyVmomiObjectJSONEncoder().encode(obj))

    def transform(self, ids, rawdata):
        result = {}
        for obj in rawdata:
            objid = unquote(obj.obj).split(':')[-1]
            ps = {}
            for prop in obj.propSet:
                ps[unquote(prop.name)] = self.jsonify_vsphere_obj(prop.val)
            result[objid] = ps
        return (not ids or sorted(result.keys()) == sorted(ids), result)


def unquote(item):
    return str(item).strip("'")
    def upload(self):
        ''' Upload.  If a host is unreachable then try another. '''
        for host_mount in self.datastore.host:
            try:
                self._esxi = host_mount.key
                if self.debounce:
                    same, hash = self._destination_exists()
                    if same:
                        self.module.exit_json(changed=False)
                self._put(self.destination_path, self.data)
                if self.debounce:
                    self._put(self.destination_sha256_path, hash)
                self.module.exit_json(changed=True)
            except Exception as e:
                self._history.append(to_native(e))
        self.module.fail_json(msg='Unable to upload.', reason=self._history)

    def _destination_exists(self):
        '''
            Check to see if the file already exists and has a corresponding
            .sha256 file on the destination.  If so, this operation can be
            idempotent by reading the .sha256 file, and calculating the local
            SHA256, and if they match then there is nothing to do.

            Returns:
                ( same, hash )
        '''
        local_hash = self._local_hash()
        self.module.debug('LOCAL  SHA256: ' + local_hash)
        remote_hash = self._remote_hash()
        self.module.debug('REMOTE SHA256: ' + str(remote_hash))
        return (local_hash == remote_hash, local_hash)

    def _expand(self, url, params):
        ''' Returns the complete url, needed to request a ticket. '''
        return requests.Request('GET', url, params=params).prepare().url

    def _get(self, url, headers=None, params=None):
        ''' Issue a GET - on 404 response return is None otherwise text '''
        r = requests.get(url, headers=headers, params=params, verify=self.module.params['validate_certs'])
        if r.status_code == 404:
            return None
        if r.status_code == 200:
            return r.text
        raise Exception('GET {0} => {1}'.format(url, r.status_code))

    def _local_hash(self):
        '''
            Obtain and optionally cache the local hash.
        '''
        generate_sha256 = True
        if self.debounce_cache_local:
            # we regenerate the hash if the .sha256 file is
            # older than the source
            source_stat = os.stat(self.source_path)
            if os.path.exists(self.source_sha256_path):
                sha256_stat = os.stat(self.source_sha256_path)
                generate_sha256 = source_stat.st_mtime >= sha256_stat.st_mtime
        if generate_sha256:
            hash = hashlib.sha256(self.data).hexdigest()
            if self.debounce_cache_local:
                with open(self.source_sha256_path, "w") as file:
                    file.write(hash)
            return hash
        with open(self.source_sha256_path, "r") as file:
            return file.read()

    def _put(self, dest, data):
        ''' Perform an upload. '''
        url, params = self._vmware_datastore_io_url(dest)
        ticket = self.acquire_service_ticket(self._expand(url, params), 'PUT')
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(data)),
            "Cookie": 'vmware_cgi_ticket=' + ticket.id
        }
        r = requests.put(url, headers=headers, params=params, data=data, verify=self.module.params['validate_certs'])
        if r.status_code in (200, 201):
            return
        raise Exception('PUT ' + url + ' = r.status_code ' + str(r.status_code))

    def _remote_hash(self):
        '''
            Read the <destination>.sha256 file if it exists on the server.
            If it does not exist then return None
        '''
        url, params = self._vmware_datastore_io_url(self.destination_sha256_path)
        ticket = self.acquire_service_ticket(self._expand(url, params), 'GET')
        headers = {'Cookie': 'vmware_cgi_ticket=' + ticket.id}
        return self._get(url, headers=headers, params=params)

    def _vmware_datastore_io_url(self, destpath):
        ''' Constructs a URL path that ESXi accepts reliably. '''
        destpath = destpath.strip('/')  # remove leading slash if there
        params = {'dsName': self.datastore.name}
        return 'https://{0}/folder/{1}'.format(self._esxi.name, destpath), params


def main():
    spec = vmware_argument_spec()
    spec.update(dict(
        datacenter=dict(type='str', required=False),
        datastore=dict(type='str', required=True),
        source=dict(type='str', required=True),
        destination=dict(type='str', required=True),
        debounce=dict(type='str', choices=['none', 'hash', 'hashcache'], default='none')
    ))

    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    datastore_upload_mgr = VmwareDatastoreUploadMgr(module=module)
    datastore_upload_mgr.upload()


if __name__ == '__main__':
    main()
# Licensed to the StackStorm, Inc ('StackStorm') under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pyVmomi import vim, vmodl  # pylint: disable-msg=E0611
from vmwarelib.actions import BaseAction

import copy
import datetime
import json
import pyVmomi


class GetProperties(BaseAction):

    def run(self, type, property, id, raw, vsphere=None):
        """
        Leverage the Property Collector to retrieve properties from any
        Managed Object.

        Args:
        - type: vimType
        - properties: optional array of properties to get (default: all)
        - ids: optional array of MOIDs to limit results (default: all)
        - vsphere: pre-configured connection information

        Returns:
        - dict: key = moid, value = dict of properties
        """

        self.establish_connection(vsphere)
        return self.collect(self.si_content, type, property, id, raw)

