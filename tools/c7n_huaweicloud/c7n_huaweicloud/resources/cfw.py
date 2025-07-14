# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from queue import Empty

from huaweicloudsdkcfw.v1 import ChangeEipStatusRequest, EipOperateProtectReqIpInfos, EipOperateProtectReq, \
    ListEipsRequest, ListFirewallDetailRequest, CreateTagRequest, CreateTagsDto, ShowAlarmConfigRequest, \
    UpdateAlarmConfigRequest, UpdateAttackLogAlarmConfigDto, ListLogConfigRequest

from c7n.exceptions import PolicyValidationError
from c7n.utils import local_session
from tools.c7n_huaweicloud.c7n_huaweicloud.actions.base import HuaweiCloudBaseAction
from tools.c7n_huaweicloud.c7n_huaweicloud.provider import resources
from tools.c7n_huaweicloud.c7n_huaweicloud.query import QueryResourceManager, TypeInfo
from huaweicloudsdkcore.exceptions import exceptions

from c7n.filters.core import type_schema, Filter

log = logging.getLogger('custodian.huaweicloud.cfw')


@resources.register('cfw')
class CloudFirewall(QueryResourceManager):
    """Huawei Cloud Firewall

    :example:
    Define a simple policy to get all cloud firewall:

    .. code-block:: yaml

        policies:
          - name: list-cloud-firewall
            resource: huaweicloud.cfw
    """

    class resource_type(TypeInfo):
        service = 'cfw'
        enum_spec = ('list_firewall_list', 'data.records', "cfw")
        id = 'fw_instance_id'
        tag_resource_type = 'cfw-cfw'

    def augment(self, resources):
        """Enhance resource data, add extra information"""
        fw_instance_ids = [resource.get('fw_instance_id') for resource in resources]
        fw_instances = []

        # Query detail for fw_instance
        session = local_session(self.session_factory)
        client = session.client('cfw')

        for fw_instance_id in fw_instance_ids:
            try:
                request = ListFirewallDetailRequest(
                    fw_instance_id=fw_instance_id,
                    limit=1024,
                    offset=0,
                    service_type=0
                )

                # Call the API to get firewall detail
                response = client.list_firewall_detail(request)
                fw_instances.append(response.to_dict())
            except exceptions.ClientRequestException as e:
                log.error(
                    f"[resource]- [augment]- The resource:[cfw] with id:[{fw_instance_id}] is failed. cause:{str(e)}")
        return fw_instances

@CloudFirewall.filter_registry.register("eip-unprotected")
class UnprotectedEipFilter(Filter):
    """Filter EIP without protection .

        :example:

        .. code-block:: yaml

            policies:
              - name: query-eip-without-protection.
                resource: huaweicloud.cfw
                filters:
                  - type: eip-unprotected
        """
    schema = type_schema('eip-unprotected')

    def process(self, resources, event=None):
        client = self.manager.get_client()
        object_ids = set()
        unprotected_object = []

        # Get object ids
        for r in resources:
            firewall = r.get('data').get('records')[0]
            protect_objects = firewall.get('protect_objects')

            if protect_objects is not None:
                for p in protect_objects:
                    object_id = p.get('object_id')
                    # protect type: 0 (north-south), 1 (east-west) , only filter north-south protect object
                    type = p.get('type')
                    if object_id is not None and type == 0:
                        object_ids.add(object_id)

        for object_id in object_ids:
            try:
                # Call the API to get eips
                request = ListEipsRequest(
                    object_id=object_id,
                    limit=1024,
                    offset=0
                )
                response = client.list_eips(request)
                log.debug(
                    "[filters]- The filter:[eip-unprotected]  query the service:[GET /v1/{project_id}/eips/protect]  is success. ")
            except exceptions.ClientRequestException as e:
                log.error(
                    f"[filters]- The filter:[eip-unprotected] with id:[{resources.id}] is failed. cause:{str(e)}")

        # get eip protect status,protection status: 0 (enabled), or 1 (disabled).
        if response.data.records is not None:
            for r in response.data.records:
                if r.status == 1:
                    unprotected_object.append(r.to_dict())
        return unprotected_object

@CloudFirewall.action_registry.register("protect-eip")
class ProtectEip(HuaweiCloudBaseAction):
    """Action to protect eip using cloud firewall.

     :example:

     .. code-block:: yaml

         policies:
           - name: cfw-enable-eip-protection
             resource: huaweicloud.cfw
             filters:
               - type: eip-unprotected
             actions:
               - type: protect-eip
                 fwInstanceId: your cloud firewall instance id

        fwInstanceId is used to protect EIPs. It is optional.
        The default firewall is the first firewall in the current region.

     """
    schema = type_schema(
        'protect-eip',
        fwInstanceId={"type": "string"},
    )

    def process(self, resources):
        client = self.manager.get_client()
        # get firewall's object_id
        object_id = ""
        ip_infos = []
        try:
            fw_instance_id = self.data.get("fwInstanceId")
            request = ListFirewallDetailRequest(
                fw_instance_id=fw_instance_id,
                limit=1024,
                offset=0,
                service_type=0
            )

            # Call the API to get firewall detail
            response = client.list_firewall_detail(request)
            firewall = response.data.records[0]
            protect_objects = firewall.protect_objects

            if protect_objects is not None:
                for p in protect_objects:
                    obj_id = p.object_id
                    # protect type: 0 (north-south), 1 (east-west) , only filter north-south protect object
                    type = p.type
                    if obj_id is not None and type == 0:
                        object_id = obj_id
                        break

            request = self.init_request(object_id, resources, fw_instance_id, ip_infos)
            # enable eip protection
            response = client.change_eip_status(request)
            log.info(
                f"[actions]- [protect-eip] The resource:[cfw] with id:[{fw_instance_id}]  protect eip with object id:{object_id}  is success.")
        except exceptions.ClientRequestException as e:
            log.error(
                f"[actions]- [protect-eip]- The resource:[cfw] with id:[{fw_instance_id}]  protect eip with object id:{object_id}  is failed. cause: {str(e)} ")
            raise e

    def init_request(self, object_id, resources, fwInstanceId, ip_infos):
        for resource in resources:
            ip_info = EipOperateProtectReqIpInfos(
                id=resource.get('id'),
                public_ip=resource.get('public_ip'),
                public_ipv6=resource.get('public_ipv6')
            )
            ip_infos.append(ip_info)
        request = ChangeEipStatusRequest(fw_instance_id=fwInstanceId)
        request.body = EipOperateProtectReq(
            ip_infos=ip_infos,
            status=0,
            object_id=object_id,
        )

        return request

    def perform_action(self, resource):
        return super().perform_action(resource)

@CloudFirewall.filter_registry.register("firewall-untagged")
class UntaggedFirewallFilter(Filter):
    """Filter firewall without tag .

        :example:

        .. code-block:: yaml

            policies:
              - name: query-firewall-without-tag.
                resource: huaweicloud.cfw
                filters:
                  - type: firewall-untagged
        """
    schema = type_schema('firewall-untagged')

    def process(self, resources, event=None):
        untagged_fw_instance_ids = []

        for r in resources:
            firewall = r.get('data').get('records')[0]
            tag = firewall.get('tags')

            try:
                # tag is none or empty
                if tag is None or tag == "{}":
                    untagged_fw_instance_ids.append(firewall.get('fw_instance_id'))
            except exceptions.ClientRequestException as e:
                log.error(
                    f"[filters]- The filter:[firewall-untagged] with id:[{firewall.get('fw_instance_id')}] is failed. cause:{str(e)}")
                raise e
        return untagged_fw_instance_ids

@CloudFirewall.action_registry.register("create-tags")
class CreateFirewallTags(HuaweiCloudBaseAction):
    """Action to create firewall tags. action can apply multiple tags to multiple firewall
    instances. users can list all instances and tags to be operated in the policy, or list
    the default tag, which will be added to the firewalls without tags.

     :example:

     .. code-block:: yaml

         policies:
           - name: cfw-create-tags
             resource: huaweicloud.cfw
             filters:
               - type: firewall-untagged
             actions:
                - type: create-tags
                    default_tags:
                        - tags:
                            - key: "Environment"
                              value: "dev"
                    tag_infos:
                        - fw_instance_ids: ["fw-001", "fw-002", "fw-003"]
                          tags:
                              - key: "Environment"
                                value: "Production"
                              - key: "Criticality"
                                value: "High"
                          - fw_instance_ids: ["fw-004", "fw-005"]
                            tags:
                              - key: "Environment"
                                value: "Staging"
     """
    schema = type_schema(
        'create-tags',
        required="default_tags",
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
        }},
        default_tags={"type": "array", "items": {
            "tags": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "key": "string", "value": "string"
                }
            }}
        }}
    )

    def process(self, resources):
        client = self.manager.get_client()
        tag_infos = self.data.get("tag_infos")
        default_tags = self.data.get("default_tags")
        default_tag_fw_instance_ids = resources
        if tag_infos is not None:
            for tag_info in tag_infos:
                for fw_instance_id in tag_info.get("fw_instance_ids"):
                    # if this firewall is untagged
                    if fw_instance_id in resources:
                        try:
                            default_tag_fw_instance_ids.remove(fw_instance_id)
                            createTagRequest = CreateTagRequest(fw_instance_id=fw_instance_id,
                                                                body=CreateTagsDto(tag_info.get("tags")))
                            createTagResponse = client.create_tag(createTagRequest)
                            log.info(
                                f"[actions]- [create-tags] The resource:[cfw] with id:[{fw_instance_id}]  create tag success.")
                        except exceptions.ClientRequestException as e:
                            log.error(
                                f"[actions]- [create-tags]- The resource:[cfw] with id:[{fw_instance_id}]  create tag failed. cause: {str(e)} ")
                            raise
                    else:
                        log.error(
                            f"[actions]- [create-tags]- The resource:[cfw] with id:[{fw_instance_id}]  create tag failed. cause: firewall doesn't exist or already have tags")
        # create default tags
        if default_tag_fw_instance_ids is not None and len(default_tag_fw_instance_ids) > 0:
            for fw_instance_id in default_tag_fw_instance_ids:
                try:
                    createTagRequest = CreateTagRequest(fw_instance_id=fw_instance_id,
                                                        body=CreateTagsDto(default_tags.get("tags")))
                    createTagResponse = client.create_tag(createTagRequest)
                    log.info(
                        f"[actions]- [create-tags] The resource:[cfw] with id:[{fw_instance_id}]  create default tag success.")
                except exceptions.ClientRequestException as e:
                    log.error(
                        f"[actions]- [create-tags]- The resource:[cfw] with id:[{fw_instance_id}]  create default tag failed. cause: {str(e)} ")
                    raise

    def perform_action(self, resource):
        return super().perform_action(resource)

@CloudFirewall.filter_registry.register("alarm-config-status")
class alarmDisabledFirewallFilter(Filter):
    """Filter firewall with alarm disable .user can choice alarm types they want to
    check,If alarm_type  is not filled, all types are selected by default.

        :example:

        .. code-block:: yaml

            policies:
                - name: check-firewall-alarm-status
                  resource: huaweicloud.cfw
                  filters:
                    - type: alarm-config-status
                    alarm_types: # Optional
                        - "attack"
                        - "traffic threshold crossing"
                        - "EIP unprotected"
                        - "threat intelligence"

        """
    schema = type_schema(
        'alarm-config-status',
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
        # get alarm types
        alarm_types = self.data.get('alarm_types')
        if alarm_types is not None:
            alarm_types = [self.ALARM_TYPE_MAPPING[a] for a in alarm_types]
        else:
            alarm_types = [0, 1, 2, 3]

        client = self.manager.get_client()
        fw_instance_ids = []

        for record in resources:
            firewall = record.get('data').get('records')[0]
            fw_instance_id = firewall.get('fw_instance_id')

            try:
                # get alarm config
                request = ShowAlarmConfigRequest(fw_instance_id=fw_instance_id)
                response = client.show_alarm_config(request)
                log.debug(
                    "[filters]- The filter:[alarm-config-status]  query the service:[GET /v1/{project_id}/cfw/alarm/config]  is success.")

                # get firewall with alarm disabled
                try:
                    alarm_configs = response.alarm_configs
                    for alarm_config in alarm_configs:
                        if alarm_config.alarm_type in alarm_types and alarm_config.enable_status == 0:
                            fw_instance_ids.append(fw_instance_id)
                            break
                except Exception as e:
                    log.error(
                        f"[filters]- The filter:[alarm-config-status] with id:[{firewall.get('fw_instance_id')}] is failed. cause:{str(e)}")
                    raise e

            except exceptions.ClientRequestException as e:
                log.error(
                    f"[filters]- The filter:[alarm-config-status] with id:[{firewall.get('fw_instance_id')}] is failed. cause:{str(e)}")
                raise e

        return fw_instance_ids

    ALARM_TYPE_MAPPING = {
        'attack': 0,
        'traffic threshold crossing': 1,
        'EIP unprotected': 2,
        'threat intelligence': 3
    }

@CloudFirewall.action_registry.register("update-firewall-alarm-config")
class UpdateFirewallAlarmConfig(HuaweiCloudBaseAction):
    """Action to update firewall alarm configuration.For alarm severity. If the value
    of type is 0 or 3, the value of severity can be one or more values of CRITICAL,
     HIGH, MEDIUM, and LOW combined. If the value of type is 2, severity can only be 3.

         :example:

         .. code-block:: yaml

             policies:
               - name: cfw-create-tags
                 resource: huaweicloud.cfw
                 filters:
                   - type: alarm-config-status
                     alarm_types: # Optional
                        - "attack"
                        - "traffic threshold crossing"
                        - "EIP unprotected"
                        - "threat intelligence"
                 actions:
                    - type: update-firewall-alarm-config
                        alarm_time_period: 0
                        alarm_types: # Optional
                            - "attack"
                            - "traffic threshold crossing"
                            - "EIP unprotected"
                            - "threat intelligence"
                        frequency_count: 10
                        frequency_time: 60
                        severity: "CRITICAL,HIGH,MEDIUM,LOW"
                        topic_urn: "urn:**"
                        username: "cfw-admin"
         """
    schema = type_schema(
        'update-firewall-alarm-config',
        required=["alarm_time_period", "frequency_count", "frequency_time", "frequency_time", "severity",
                  "topic_urn", "username"],  # 必填参数
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
            'minimum': 1
        },
        frequency_time={
            'type': 'integer',
            'minimum': 1
        },
        severity={
            'type': 'string',
            'enum': [0, 1, 2, 3, 4],
            'default': 0
        },
        topic_urn={
            'type': 'string'
        },
        # 可选参数
        language={
            'type': 'string',
            'enum': ['zh-cn', 'en-us'],
            'default': 'en-us'
        },
        username={
            'type': 'string'
        }
    )

    def process(self, resources):
        client = self.manager.get_client()

        for fw_instance_id in resources:
            alarm_types = self.data.get('alarm_types')

            if alarm_types is not None:
                alarm_types = [self.ALARM_TYPE_MAPPING[a] for a in alarm_types]
            else:
                alarm_types = [0, 1, 2, 3]

            for alarm_type in alarm_types:
                request = self.init_request(alarm_type, fw_instance_id)
                try:
                    client.update_alarm_config(request)
                    log.info(
                        f"[actions]- [update-firewall-alarm-config] The resource:[cfw] with id:[{fw_instance_id}]  update alarm config success.")
                except exceptions.ClientRequestException as e:
                    log.error(
                        f"[actions]- [update-firewall-alarm-config]- The resource:[cfw] with id:[{fw_instance_id}]  update alarm config failed cause: {str(e)} ")
                    raise

    def init_request(self, alarm_type, fw_instance_id):
        request = UpdateAlarmConfigRequest(fw_instance_id=fw_instance_id)

        # process severity
        severity = self.data.get("severity")
        if alarm_type == 0 or alarm_type ==4:
            severity_split = severity.split(",")
            for sev in severity_split:
                if sev not in self.SEVERITY:
                    log.error(
                        f"[actions]- [update-firewall-alarm-config]- The resource:[cfw] with id:[{fw_instance_id}]  param severity error")
                    raise PolicyValidationError("param severity error")
        elif alarm_type == 1:
            severity = "2"
        elif alarm_type == 2:
            severity = "3"

        request.body = UpdateAttackLogAlarmConfigDto(
            alarm_time_period=self.data.get("alarm_time_period"),
            alarm_type=alarm_type,
            enable_status=1,
            frequency_count=self.data.get("frequency_count"),
            frequency_time=self.data.get("frequency_time"),
            language=self.data.get("language"),
            severity=severity,
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

    SEVERITY= ["CRITICAL","HIGH","MEDIUM","LOW"]

@CloudFirewall.filter_registry.register("firewall-logged")
class UnloggedFirewallFilter(Filter):
    """Filter firewall with lts disable .

        :example:

        .. code-block:: yaml

            policies:
              - name: query-firewall-with-lts-disable.
                resource: huaweicloud.cfw
                filters:
                  - type: firewall-logged
        """
    schema = type_schema('firewall-logged')

    def process(self, resources, event=None):
        client = self.manager.get_client()
        unlogged_fw_instance_ids = []

        for record in resources:
            firewall = record.get('data').get('records')[0]
            fw_instance_id = firewall.get('fw_instance_id')

            try:
                request = ListLogConfigRequest(fw_instance_id=fw_instance_id)
                response = client.list_log_config(request)
                r = response.data

                # If lts_enable is 1 in the response, log  is enabled. If lts_enable is 0 or response is empty, log is disabled.
                if r is None or r.lts_enable == 0:
                    unlogged_fw_instance_ids.append(fw_instance_id)
            except exceptions.ClientRequestException as e:
                log.error(
                    f"[filters]- The filter:[firewall-logged] with id:[{firewall.get('fw_instance_id')}] is failed. cause:{str(e)}")
                raise e

        return unlogged_fw_instance_ids
