# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os

from huaweicloudsdkcfw.v1 import ChangeEipStatusRequest, EipOperateProtectReqIpInfos, EipOperateProtectReq, \
    ListEipsRequest

from tools.c7n_huaweicloud.c7n_huaweicloud.actions.base import HuaweiCloudBaseAction
from tools.c7n_huaweicloud.c7n_huaweicloud.provider import resources
from tools.c7n_huaweicloud.c7n_huaweicloud.query import QueryResourceManager, TypeInfo
from huaweicloudsdkcore.exceptions import exceptions

from c7n.filters.core import type_schema, Filter

log = logging.getLogger('custodian.huaweicloud.cfw')


@resources.register('cfw')
class Cfw(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'cfw'
        # API info for enumerating resources: (operation name, result list field, pagination type)
        enum_spec = ('list_firewall_list', 'data.records', "cfw")
        # Resource unique identifier field name
        id = 'fw_instance_name'

@resources.register('cfw-firewall')
class Firewall(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'cfw-detail'
        # API info for enumerating resources: (operation name, result list field, pagination type)
        enum_spec = ('list_firewall_detail', 'data.records', "cfw-detail")
        # Resource unique identifier field name
        id = 'fw_instance_id'

@Firewall.filter_registry.register("eip-unprotected")
class EipUnprotected(Filter):
    schema = type_schema('eip-unprotected')

    def process(self, resources, event=None):
        client = self.manager.get_resource_manager('cfw-firewall').get_client()
        object_ids = []
        for record in resources:
            protect_objects = record.get('protect_objects')
            for protect_object in protect_objects :
                if protect_object.get('type') == 0 :
                    object_id = protect_object.get('object_id')
                    try:
                        request = ListEipsRequest(object_id=object_id, limit=1024, offset=0)
                        response = client.list_eips(request)
                    except exceptions.ClientRequestException as ex:
                        log.exception("Unable to filter unprotected eip."
                                      "RequestId: %s, Reason: %s." %
                                      (ex.request_id, ex.error_msg))
                    if response.data.records is not None:
                        for r in response.data.records :
                            if r.status == 1 :
                                object_ids.append(object_id)
        return object_ids



@Firewall.action_registry.register("protect-eip")
class ProtectEip(HuaweiCloudBaseAction):
    schema = type_schema(
        'protect-eip',
        fwInstanceId={"type": "string"},
    )

    def process(self, resources):
        fwInstanceId = self.data.get("fwInstanceId")
        client = self.manager.get_client()
        ip_infos = []
        for object_id in resources :
            listEipRequest = ListEipsRequest(object_id = object_id, limit=1024, offset=0)
            listEipResponse = client.list_eips(listEipRequest)
            for r in listEipResponse.data.records:
                if r.status == 1:
                    ip_info = EipOperateProtectReqIpInfos(id=r.id, public_ip=r.public_ip)
                    ip_infos.append(ip_info)

            request = self.init_request(object_id, ip_infos, fwInstanceId)
            try:
                response = client.change_eip_status(request)
            except exceptions.ClientRequestException as e:
                log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
                raise
        return json.dumps(response.to_dict())

    def init_request(self, object_id, ip_infos, fwInstanceId):
        request = ChangeEipStatusRequest(fw_instance_id=fwInstanceId)
        request.body = EipOperateProtectReq(
            ip_infos= ip_infos,
            status= 0,
            object_id= object_id,
        )

        return request

    def perform_action(self, resource):
        return super().perform_action(resource)
