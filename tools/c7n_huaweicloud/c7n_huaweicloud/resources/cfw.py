# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from queue import Empty

from huaweicloudsdkcfw.v1 import ChangeEipStatusRequest, EipOperateProtectReqIpInfos, EipOperateProtectReq, \
    ListEipsRequest, ListFirewallDetailRequest, CreateTagRequest, CreateTagsDto, ShowAlarmConfigRequest, \
    UpdateAlarmConfigRequest, UpdateAttackLogAlarmConfigDto, ListLogConfigRequest

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
        id = 'fw_instance_id'

@resources.register('cfw-firewall')
class Firewall(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'cfw-detail'
        # API info for enumerating resources: (operation name, result list field, pagination type)
        enum_spec = ('list_firewall_detail', 'data.records', "cfw-detail")
        # Resource unique identifier field name
        id = 'fw_instance_id'

@Cfw.filter_registry.register("eip-unprotected")
class EipUnprotected(Filter):
    schema = type_schema('eip-unprotected')

    def process(self, resources, event=None):
        client = self.manager.get_client()
        protect_objects = set()
        object_ids = []
        for record in resources:
            fw_instance_id = record.get('fw_instance_id')
            try:
                list_firewall_detail_request = ListFirewallDetailRequest(fw_instance_id=fw_instance_id, limit=1024, offset=0, service_type=0)
                list_firewall_detail_response = client.list_firewall_detail(list_firewall_detail_request)
            except exceptions.ClientRequestException as ex:
                log.exception("Unable to filter unprotected eip."
                              "RequestId: %s, Reason: %s." %
                              (ex.request_id, ex.error_msg))
            list_firewall_detail_response_records = list_firewall_detail_response.data.records
            if list_firewall_detail_response_records is not None:
                for protect_object in list_firewall_detail_response_records.get('protect_objects'):
                    protect_objects.add(protect_object)

        for protect_object in protect_objects:
            if protect_object.type == 0:
                object_id = protect_object.get('object_id')
                try:
                    request = ListEipsRequest(object_id=object_id, limit=1024, offset=0)
                    response = client.list_eips(request)
                except exceptions.ClientRequestException as ex:
                    log.exception("Unable to filter unprotected eip."
                                  "RequestId: %s, Reason: %s." %
                                  (ex.request_id, ex.error_msg))
                if response.data.records is not None:
                    for r in response.data.records:
                        if r.status == 1:
                            object_ids.append(object_id)

        return object_ids

@Cfw.filter_registry.register("firewall-untagged")
class FirewallUntagged(Filter):
    schema = type_schema('firewall-untagged')

    def process(self, resources, event=None):
        client = self.manager.get_client()
        untagged_fw_instance_ids = []
        for record in resources:
            fw_instance_id = record.get('fw_instance_id')
            try:
                list_firewall_detail_request = ListFirewallDetailRequest(fw_instance_id=fw_instance_id, limit=1024, offset=0, service_type=0)
                list_firewall_detail_response = client.list_firewall_detail(list_firewall_detail_request)
            except exceptions.ClientRequestException as ex:
                log.exception("Unable to filter unprotected eip."
                              "RequestId: %s, Reason: %s." %
                              (ex.request_id, ex.error_msg))
            list_firewall_detail_response_records = list_firewall_detail_response.data.records
            if list_firewall_detail_response_records[0].tags is None:
                untagged_fw_instance_ids.append(fw_instance_id)

        return untagged_fw_instance_ids

@Cfw.filter_registry.register("firewall-logged")
class FirewallUnlogged(Filter):
    schema = type_schema('firewall-logged')

    def process(self, resources, event=None):
        client = self.manager.get_client()
        unlogged_fw_instance_ids = []
        for record in resources:
            fw_instance_id = record.get('fw_instance_id')
            try:
                list_log_config_request = ListLogConfigRequest(fw_instance_id=fw_instance_id)
                list_log_config_response = client.list_log_config(list_log_config_request)
            except exceptions.ClientRequestException as ex:
                log.exception("Unable to filter unprotected eip."
                              "RequestId: %s, Reason: %s." %
                              (ex.request_id, ex.error_msg))
            list_log_config_response_records = list_log_config_response.data
            if list_log_config_response_records.lts_enable == 0:
                unlogged_fw_instance_ids.append(fw_instance_id)

        return unlogged_fw_instance_ids

@Cfw.filter_registry.register("alarm-config-check")
class FirewallUntagged(Filter):
    schema = type_schema(
        'alarm-config-check',
        alarm_types={
            'type': 'array',
            'items': {
                'type': 'string',
                'enum': [
                    'attack',
                    'traffic threshold crossing',
                    'EIP unprotected',
                    'threat intelligence'
                ]
            },
        }
    )
    def process(self, resources, event=None):
        alarm_types=self.data.get('alarm_types')
        if alarm_types is not None:
            alarm_types = [self.ALARM_TYPE_MAPPING[a] for a in alarm_types]
        client = self.manager.get_client()
        fw_instance_ids = []
        for record in resources:
            fw_instance_id = record.get('fw_instance_id')
            try:
                show_alarm_config_request = ShowAlarmConfigRequest(fw_instance_id=fw_instance_id)
                show_alarm_config_response = client.show_alarm_config(show_alarm_config_request)
            except exceptions.ClientRequestException as ex:
                log.exception("Unable to filter unprotected eip."
                              "RequestId: %s, Reason: %s." %
                              (ex.request_id, ex.error_msg))
            alarm_configs = show_alarm_config_response.alarm_configs
            for alarm_config in alarm_configs:
                if alarm_config.alarm_type in alarm_types and alarm_config.enable_status == 0:
                    fw_instance_ids.append(fw_instance_id)
                    break

        return fw_instance_ids

    ALARM_TYPE_MAPPING = {
        'attack': 0,
        'traffic threshold crossing': 1,
        'EIP unprotected': 2,
        'threat intelligence': 3
    }

@Cfw.action_registry.register("update-firewall-alarm-config")
class UpdateFirewallAlarmConfig(HuaweiCloudBaseAction):
    schema = type_schema(
        'update-firewall-alarm-config',
        required=["alarm_time_period","alarm_types","frequency_count","frequency_time","frequency_time","severity","topic_urn","username"],        # 必填参数
        alarm_time_period={
            'type': 'integer',
            'enum': [0, 1],
            'default': 0
        },
        alarm_types={
            'type': 'array',
            'items': {
                'type': 'string',
                'enum': [
                    'attack',
                    'traffic threshold crossing',
                    'EIP unprotected',
                    'threat intelligence'
                ]
            }
        },
        frequency_count={
            'type': 'integer',
            'minimum': 1,
        },
        frequency_time={
            'type': 'integer',
            'minimum': 1,
        },
        severity={
            'type': 'string',
            'enum': [0, 1, 2, 3, 4],
            'default': 0
        },
        topic_urn={
            'type': 'string',
        },
        # 可选参数
        language={
            'type': 'string',
            'enum': ['zh-cn', 'en-us'],
            'default': 'en-us'
        },
        username={
            'type': 'string',
        }
    )

    def process(self, resources):
        client = self.manager.get_client()
        for fwInstanceId in resources :
            alarm_types = self.data.get('alarm_types')
            if alarm_types is not None:
                alarm_types = [self.ALARM_TYPE_MAPPING[a] for a in alarm_types]
                for alarm_type in alarm_types:
                    request = self.init_request(alarm_type,fwInstanceId)
                    try:
                        response = client.update_alarm_config(request)
                    except exceptions.ClientRequestException as e:
                        log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
                        raise
        return json.dumps(response.to_dict())

    def init_request(self, alarm_type,fwInstanceId):
        request = UpdateAlarmConfigRequest(fw_instance_id=fwInstanceId)
        request.body = UpdateAttackLogAlarmConfigDto(
            alarm_time_period=self.data.get("alarm_time_period"),
            alarm_type=alarm_type,
            enable_status=1,
            frequency_count=self.data.get("frequency_count"),
            frequency_time=self.data.get("frequency_time"),
            language=self.data.get("language"),
            severity=self.data.get("severity"),
            topic_urn=self.data.get("topic_urn"),
            username=self.data.get("username"),
        )
        return request

    def perform_action(self, resource):
        return super().perform_action(resource)

    ALARM_TYPE_MAPPING = {
        'attack': 0,
        'traffic threshold crossing': 1,
        'EIP unprotected': 2,
        'threat intelligence': 3
    }

@Cfw.action_registry.register("protect-eip")
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

@Cfw.action_registry.register("create-tags")
class CreateTags(HuaweiCloudBaseAction):
    schema = type_schema(
        'create-tags',
        required="tag_infos",
        tag_infos={"type": "array", "items": {
            "type": "object",
            "properties": {
                "fw_instance_ids": {"type": "array", "items": {"type": "string"}},
                "tags": {"type": "array", "items": {
                    "type": "object",
                    "properties": {
                        "key": "string", "value": "string"
                    }
                }}
            }
        }}
    )

    def process(self, resources):
        client = self.manager.get_client()
        tag_infos = self.data.get("tag_infos")
        if tag_infos is not None:
            for tag_info in tag_infos:
                for fw_instance_id in tag_info.get("fw_instance_ids"):
                    if fw_instance_id in resources:
                        try:
                            createTagRequest = CreateTagRequest(fw_instance_id=fw_instance_id, body=CreateTagsDto(tag_info.get("tags")))
                            createTagResponse = client.create_tag(createTagRequest)
                        except exceptions.ClientRequestException as e:
                            log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
                            raise

        return json.dumps(createTagResponse.to_dict())

    def perform_action(self, resource):
        return super().perform_action(resource)


def log_and_catch(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except exceptions.ClientRequestException as e:
            log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
            raise

    return wrapper
