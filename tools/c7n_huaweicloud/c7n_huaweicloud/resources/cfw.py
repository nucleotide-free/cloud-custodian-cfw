# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import copy
import logging
import re

from huaweicloudsdkcfw.v1 import (ChangeEipStatusRequest, EipOperateProtectReqIpInfos,
                                  EipOperateProtectReq, ListEipsRequest, ListFirewallDetailRequest,
                                  CreateTagRequest, CreateTagsDto, ShowAlarmConfigRequest,
                                  UpdateAlarmConfigRequest, UpdateAttackLogAlarmConfigDto,
                                  ListLogConfigRequest, UpdateLogConfigRequest, LogConfigDto,
                                  ListAclRulesRequest, AddAclRuleRequest, RuleServiceDto,
                                  RuleAddressDtoForRequest, OrderRuleAclDto, AddRuleAclDtoRules,
                                  AddRuleAclDto)
from huaweicloudsdklts.v2 import LogGroup, ListLogGroupsRequest, ListLogStreamRequest

from c7n.exceptions import PolicyValidationError
from c7n.utils import local_session
from tools.c7n_huaweicloud.c7n_huaweicloud.actions.base import HuaweiCloudBaseAction
from tools.c7n_huaweicloud.c7n_huaweicloud.provider import resources
from tools.c7n_huaweicloud.c7n_huaweicloud.query import QueryResourceManager, TypeInfo
from huaweicloudsdkcore.exceptions import exceptions

from c7n.filters.core import type_schema, Filter

log = logging.getLogger('custodian.huaweicloud.cfw')
DEFAULT_LIMIT_SIZE = 200


@resources.register('cfw')
class Cfw(QueryResourceManager):
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
                    limit=DEFAULT_LIMIT_SIZE,
                    offset=0,
                    service_type=0
                )

                # Call the API to get firewall detail
                response = client.list_firewall_detail(request)
                fw_instances.append(response.to_dict())
            except exceptions.ClientRequestException as e:
                log.error(
                    f"[resource]- [augment]- The resource:[cfw] with id:[{fw_instance_id}]"
                    f" is failed. cause:{str(e)}")
        return fw_instances


@Cfw.filter_registry.register("check-unprotected-eip")
class UnprotectedEipFilter(Filter):
    """Filter EIP without protection .

        :example:

        .. code-block:: yaml

            policies:
              - name: query-eip-without-protection.
                resource: huaweicloud.cfw
                filters:
                  - type: check-unprotected-eip
        """
    schema = type_schema('check-unprotected-eip')

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
                    # protect type: 0 (north-south), 1 (east-west)
                    # only filter north-south protect object
                    type = p.get('type')
                    if object_id is not None and type == 0:
                        object_ids.add(object_id)

        for object_id in object_ids:
            try:
                # Call the API to get eips
                request = ListEipsRequest(
                    object_id=object_id,
                    limit=DEFAULT_LIMIT_SIZE,
                    offset=0
                )
                response = client.list_eips(request)
                log.info("[filters]-{check-unprotected-eip} "
                         "The resource:[cfw] with request:[%s] "
                         "query eips is success.", request)
            except exceptions.ClientRequestException as e:
                log.error("[filters]-{check-unprotected-eip} "
                          "The resource:[cfw] with request:[%s] "
                          "query eips is failed, cause: "
                          "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                          request, e.status_code, e.request_id, e.error_code, e.error_msg)
                raise
        # get eip protect status,protection status: 0 (enabled), or 1 (disabled).
        if response.data.records is not None:
            for r in response.data.records:
                if r.status == 1:
                    unprotected_object.append(r.to_dict())
        return unprotected_object


@Cfw.action_registry.register("protect-eip")
class ProtectEip(HuaweiCloudBaseAction):
    """Action to protect eip using cloud firewall.firewall with certain fwInstanceId
    is used to protect EIPs. It is optional.The default firewall is the first firewall
     in the current region.

     :example:

     .. code-block:: yaml

         policies:
           - name: cfw-enable-eip-protection
             resource: huaweicloud.cfw
             filters:
               - type: check-unprotected-eip
             actions:
               - type: protect-eip
                 fwInstanceId: your cloud firewall instance id

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
                limit=DEFAULT_LIMIT_SIZE,
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
                    # protect type: 0 (north-south), 1 (east-west)
                    # only filter north-south protect object
                    type = p.type
                    if obj_id is not None and type == 0:
                        object_id = obj_id
                        break

            request = self.init_request(object_id, resources, fw_instance_id, ip_infos)
            # enable eip protection
            response = client.change_eip_status(request)
            log.info("[actions]-{protect-eip} "
                     "The resource:[cfw] with request:[%s] "
                     "protect eip with object id [%s] is success.", request, object_id)
        except exceptions.ClientRequestException as e:
            log.error("[actions]-{protect-eip} "
                      "The resource:[cfw] with request:[%s] "
                      "protect eip with object id [%s] is failed, cause: "
                      "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                      request, object_id, e.status_code, e.request_id, e.error_code, e.error_msg)
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


@Cfw.filter_registry.register("check-untagged-firewall")
class UntaggedFirewallFilter(Filter):
    """Filter firewall without tag .

        :example:

        .. code-block:: yaml

            policies:
              - name: query-firewall-without-tag.
                resource: huaweicloud.cfw
                filters:
                  - type: check-untagged-firewall
        """
    schema = type_schema('check-untagged-firewall')

    def process(self, resources, event=None):
        untagged_fw_instance_ids = []

        for r in resources:
            firewall = r.get('data').get('records')[0]
            tag = firewall.get('tags')

            try:
                # tag is none or empty
                if tag is None or tag == "{}":
                    untagged_fw_instance_ids.append(firewall.get('fw_instance_id'))
            except Exception as e:
                log.error(
                    f"[filters]- The resource:[cfw] with id:[{firewall.get('fw_instance_id')}]"
                    f" query untagged firewall is failed. cause:{str(e)}")
                raise e
        return untagged_fw_instance_ids


@Cfw.action_registry.register("create-tags")
class CreateFirewallTags(HuaweiCloudBaseAction):
    """Action to create firewall tags. action can apply multiple tags to multiple firewall
    instances. users can list all instances and tags to be operated in the policy, or list
    the default tag, which will be added to the firewalls without tags.

     :example:

     .. code-block:: yaml

         policies:
          - name: cfw-create-tags
            resource: huaweicloud.cfw
            actions:
              - type: create-tags
                default_tags:
                  - key: "Environment"
                    value: "dev"
                tag_infos:
                  - fw_instance_ids: ["************-a68-8186-c***********9"]
                    tags:
                      - key: "Environment"
                        value: "Production"
                      - key: "Criticality"
                        value: "High"
     """
    schema = type_schema(
        'create-tags',
        required=["default_tags"],
        tag_infos={"type": "array", "items": {
            "type": "object",
            "properties": {
                "fw_instance_ids": {"type": "array", "items": {"type": "string"}},
                "tags": {"type": "array", "items": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string"},
                        "value": {"type": "string"}
                    }
                }}
            }
        }},
        default_tags={"type": "array", "items": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"}
            }
        }}
    )

    def process(self, resources):
        client = self.manager.get_client()
        tag_infos = self.data.get("tag_infos")
        default_tags = self.data.get("default_tags")
        for record in resources:
            firewall = record.get('data').get('records')[0]
            fwInstanceId = firewall.get('fw_instance_id')

            for tag_info in tag_infos:
                try:
                    if fwInstanceId in tag_info.get("fw_instance_ids"):
                        req = CreateTagRequest(fw_instance_id=fwInstanceId,
                                               body=CreateTagsDto(tag_info.get("tags")))
                        client.create_tag(req)
                        log.info("[actions]-{create-tags} "
                                 "The resource:[cfw] with request:[%s] "
                                 "create tag is success.", req)
                    else:
                        request = CreateTagRequest(fw_instance_id=fwInstanceId,
                                                   body=CreateTagsDto(tags=default_tags))
                        client.create_tag(request)
                        log.info("[actions]-{create-tags} "
                                 "The resource:[cfw] with request:[%s] "
                                 "create default tag is success.", request)
                except exceptions.ClientRequestException as e:
                    log.error("[actions]-{create-tags} "
                              "The resource:[cfw] with request:[%s] "
                              "create default tag is failed, cause: "
                              "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                              request, e.status_code, e.request_id, e.error_code, e.error_msg)
                    raise
                except Exception as e:
                    log.error("[actions]-{create-tags} "
                              "The resource:[cfw] with request:[%s] "
                              "create default tag  is failed, cause: [%s] ",
                              str(e))
                    raise

    def perform_action(self, resource):
        return super().perform_action(resource)


@Cfw.filter_registry.register("check-alarm-config")
class alarmDisabledFirewallFilter(Filter):
    """Filter firewall with alarm disabled .user can choice alarm types they want to
    check,If alarm_type is not filled, all types(attack/traffic threshold crossing/
    EIP unprotected/threat intelligence) are selected by default.

        :example:

        .. code-block:: yaml

            policies:
                - name: check-firewall-alarm-status
                  resource: huaweicloud.cfw
                  filters:
                    - type: check-alarm-config
                    alarm_types: # Optional
                        - "attack"
                        - "traffic threshold crossing"
                        - "EIP unprotected"
                        - "threat intelligence"

        """
    schema = type_schema(
        'check-alarm-config',
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
                log.info(
                    "[filters]-{check-alarm-config} The resource:[cfw] with request:[%s] "
                    "query firewall with alarm disabled is success.", request)

                # get firewall with alarm disabled
                try:
                    alarm_configs = response.alarm_configs
                    for alarm_config in alarm_configs:
                        if (alarm_config.alarm_type in alarm_types
                                and alarm_config.enable_status == 0):
                            fw_instance_ids.append(fw_instance_id)
                            break
                except Exception as e:
                    log.error(
                        f"[filters]- The filter:[check-alarm-config] "
                        f"with id:[{firewall.get('fw_instance_id')}] "
                        f"is failed. cause:{str(e)}")
                    raise e

            except exceptions.ClientRequestException as e:
                log.error("[filters]-{check-alarm-config} "
                          "The resource:[cfw] with request:[%s] "
                          "query firewall with alarm disabled is failed, cause: "
                          "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                          request, e.status_code, e.request_id, e.error_code, e.error_msg)
                raise e

        return fw_instance_ids

    ALARM_TYPE_MAPPING = {
        'attack': 0,
        'traffic threshold crossing': 1,
        'EIP unprotected': 2,
        'threat intelligence': 3
    }


@Cfw.action_registry.register("update-alarm-config")
class UpdateFirewallAlarmConfig(HuaweiCloudBaseAction):
    """Action to update firewall alarm configuration.

     alarm severity: If the value of type is 0 or 3, the value of severity can be
        one or more values of CRITICAL,HIGH, MEDIUM, and LOW combined. If the value of
        type is 2, severity can only be 3.
     alarm_time_period : 0 (all day), 1 (8:00 to 22:00)
     alarm_type : 0 (attack), 1 (traffic threshold crossing), 2 (EIP unprotected),
        3 (threat intelligence)
     frequency_count: Alarm triggering frequency.
     frequency_time : Alarm frequency time range, in minutes.
     language :zh-cn (Chinese), en-us (English)
     name : Notification group name.
     topic_urn : URN of an alarm topic.
     username : Its value is cfw.

         :example:

         .. code-block:: yaml

             policies:
               - name: cfw-update-alarm-config
                 resource: huaweicloud.cfw
                 filters:
                   - type: check-alarm-config
                     alarm_types: # Optional
                        - "attack"
                        - "traffic threshold crossing"
                        - "EIP unprotected"
                        - "threat intelligence"
                 actions:
                    - type: update-alarm-config
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
        'update-alarm-config',
        required=[
            "alarm_time_period",
            "frequency_count",
            "frequency_time",
            "frequency_time",
            "severity",
            "topic_urn",
            "username"
        ],  # 必填参数
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
            'type': 'string'
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
                    log.info("[actions]-{update-alarm-config} "
                             "The resource:[cfw] with request:[%s] "
                             "update alarm config is success.", request)
                except exceptions.ClientRequestException as e:
                    log.error("[actions]-{update-alarm-config} "
                              "The resource:[cfw] with request:[%s] "
                              "update alarm config is failed, cause: "
                              "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                              request, e.status_code, e.request_id, e.error_code, e.error_msg)
                    raise

    def init_request(self, alarm_type, fw_instance_id):
        request = UpdateAlarmConfigRequest(fw_instance_id=fw_instance_id)

        # process severity
        severity = self.data.get("severity")
        if alarm_type == 0 or alarm_type == 4:
            severity_split = severity.split(",")
            for sev in severity_split:
                if sev not in self.SEVERITY:
                    log.error(
                        f"[actions]- [update-alarm-config]- "
                        f"The resource:[cfw] with id:[{fw_instance_id}]  "
                        f"param severity error")
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

    SEVERITY = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@Cfw.filter_registry.register("check-unlogged-firewall")
class UnloggedFirewallFilter(Filter):
    """Filter firewall with lts disabled .

        :example:

        .. code-block:: yaml

            policies:
              - name: query-firewall-with-lts-disable
                resource: huaweicloud.cfw
                filters:
                  - type: check-unlogged-firewall
        """
    schema = type_schema('check-unlogged-firewall')

    def process(self, resources, event=None):
        client = self.manager.get_client()
        unlogged_fw_instance_ids = []

        for record in resources:
            firewall = record.get('data').get('records')[0]
            fw_instance_id = firewall.get('fw_instance_id')

            try:
                request = ListLogConfigRequest(fw_instance_id=fw_instance_id)
                response = client.list_log_config(request)
                log.info("[filters]-{check-unlogged-firewall} "
                         "The resource:[cfw] with request:[%s] "
                         "query firewall with lts disabled is success.", request)
                r = response.data

                # If lts_enable is 1 in the response, log  is enabled.
                # If lts_enable is 0 or response is empty, log is disabled.
                if r is None or r.lts_enable == 0:
                    unlogged_fw_instance_ids.append(fw_instance_id)
            except exceptions.ClientRequestException as e:
                log.error("[filters]-{check-unlogged-firewall} "
                          "The resource:[cfw] with request:[%s] "
                          "query firewall with lts disabled is failed, cause: "
                          "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                          request, e.status_code, e.request_id, e.error_code, e.error_msg)
                raise e

        return unlogged_fw_instance_ids


@Cfw.action_registry.register("update-log-config")
class UpdateFirewallLogConfig(HuaweiCloudBaseAction):
    """Action to enable LTS to query and visualize traffic logs, access control logs,
        and attack logs of a tenant generated more than seven days ago. All the parameters
        are required and At least one of the attack log, access log, and flow log must
        be enabled.if not enabled, log stream name can be blank .Attack logs and access
        logs are in different formats and need to be recorded in different log streams. The
        log stream will be associated with a structured CFW log template.

         :example:

         .. code-block:: yaml

             policies:
               - name: cfw-update-log-config
                 resource: huaweicloud.cfw
                 filters:
                  - type: check-unlogged-firewall
                 actions:
                    - type: update-log-config
                        lts_log_group_name: lts-group-XXX
                        lts_attack_log_stream_name: lts-topic-XXX # enable
                        lts_attack_log_stream_enable: 1
                        lts_access_log_stream_name: lts-topic-XXX # enable
                        lts_access_log_stream_enable: 1
                        lts_flow_log_stream_name:                 # disable
                        lts_flow_log_stream_enable: 0

         """
    schema = type_schema(
        'update-log-config',
        required=["lts_log_group_name",
                  "lts_attack_log_stream_name",
                  "lts_attack_log_stream_enable",
                  "lts_access_log_stream_name",
                  "lts_access_log_stream_enable",
                  "lts_flow_log_stream_name",
                  "lts_flow_log_stream_enable"],  # 必填参数
        lts_log_group_name={
            'type': 'string'
        },
        lts_attack_log_stream_name={
            'type': 'string'
        },
        lts_attack_log_stream_enable={
            'type': 'integer', 'default': 0
        },
        lts_access_log_stream_name={
            'type': 'string'
        },
        lts_access_log_stream_enable={
            'type': 'integer', 'default': 0
        },
        lts_flow_log_stream_name={
            'type': 'string'
        },
        lts_flow_log_stream_enable={
            'type': 'integer', 'default': 0
        }
    )

    def process(self, resources):
        client = self.manager.get_client()
        try:
            access_log_stream_id, attack_log_stream_id, flow_log_stream_id, log_group_id = self.validate_log_infos()

            for fw_instance_id in resources:
                request = self.init_request(fw_instance_id, log_group_id, access_log_stream_id, flow_log_stream_id,
                                            attack_log_stream_id)

                client.update_log_config(request)
                log.info("[actions]-{update-log-config} "
                         "The resource:[cfw] with request:[%s] "
                         "update log config is success.", request)
        except exceptions.ClientRequestException as e:
            log.error("[actions]-{update-log-config} "
                      "The resource:[cfw] with request:[%s] "
                      "update log config is failed, cause: "
                      "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                      request, e.status_code, e.request_id, e.error_code, e.error_msg)
            raise

    def validate_log_infos(self):
        # get log group id
        log_group_id, lts_client = self.validate_log_group_name()
        # get log stream id
        access_log_stream_id, attack_log_stream_id, flow_log_stream_id = (
            self.validate_log_stream_names(log_group_id, lts_client))

        return access_log_stream_id, attack_log_stream_id, flow_log_stream_id, log_group_id

    def validate_log_stream_names(self, log_group_id, lts_client):
        # get stream by group id
        list_log_stream_req = ListLogStreamRequest(log_group_id=log_group_id)
        log_stream_resp = lts_client.list_log_stream(list_log_stream_req)
        log.info("[actions]-{update-log-config} "
                 "The resource:[cfw] with request:[%s] "
                 "query log stream is success.", list_log_stream_req)

        # get stream id by stream name
        access_log_stream_id = flow_log_stream_id = attack_log_stream_id = None
        for log_stream in log_stream_resp.log_streams:
            if self.data.get("lts_attack_log_stream_name") == log_stream.log_stream_name:
                attack_log_stream_id = log_stream.log_stream_id
            elif self.data.get("lts_access_log_stream_name") == log_stream.log_stream_name:
                access_log_stream_id = log_stream.log_stream_id
            elif self.data.get("lts_flow_log_stream_name") == log_stream.log_stream_name:
                flow_log_stream_id = log_stream.log_stream_id

        # At least one of the attack log, access log and flow log must be enabled
        lts_access_log_stream_enable = self.data.get("lts_access_log_stream_enable")
        lts_attack_log_stream_enable = self.data.get("lts_attack_log_stream_enable")
        lts_flow_log_stream_enable = self.data.get("lts_flow_log_stream_enable")
        if self.is_zero_or_none(lts_access_log_stream_enable) \
                and self.is_zero_or_none(lts_attack_log_stream_enable) \
                and self.is_zero_or_none(lts_flow_log_stream_enable):
            log.error("[actions]-{update-log-config} "
                      "The resource:[cfw]"
                      "update log config is failed, cause: "
                      "At least one of the attack log, access log,"
                      " and flow log must be enabled")
            raise Exception

        # validate enabled log stream id
        if lts_access_log_stream_enable == 1 and access_log_stream_id is None \
                or lts_flow_log_stream_enable == 1 and flow_log_stream_id is None \
                or lts_attack_log_stream_enable == 1 and attack_log_stream_id is None:
            log.error("[actions]-{update-log-config} "
                      "The resource:[cfw]"
                      "update log config is failed, cause: "
                      "log stream name error")
            raise Exception

        return access_log_stream_id, attack_log_stream_id, flow_log_stream_id

    def is_zero_or_none(self, value):
        return value is None or value == 0

    def validate_log_group_name(self):
        # get log group and validate log group name
        log_group_id = ""
        lts_client = local_session(self.manager.session_factory).client('lts-stream')
        log_group_response = lts_client.list_log_groups(ListLogGroupsRequest())
        log.info("[actions]-{update-log-config} "
                 "The resource:[cfw] with response:[%s] "
                 "query log group is success.", log_group_response)
        input_log_group_name = self.data.get("lts_log_group_name")

        for log_group in log_group_response.log_groups:
            if input_log_group_name in log_group.log_group_name:
                # get log group id
                log_group_id = log_group.log_group_id

        if log_group_id == "":
            log.error("[actions]-{update-log-config} "
                      "The resource:[cfw]"
                      "update log config is failed, cause: "
                      "log_group [%s] not exist",
                      input_log_group_name)
            raise Exception

        return log_group_id, lts_client

    def init_request(self, fw_instance_id, log_group_id, access_log_stream_id, flow_log_stream_id,
                     attack_log_stream_id):
        request = UpdateLogConfigRequest(fw_instance_id=fw_instance_id, )
        request.body = LogConfigDto(
            fw_instance_id=fw_instance_id,
            lts_log_group_id=log_group_id,
            lts_enable=1,
            lts_attack_log_stream_id=attack_log_stream_id,
            lts_attack_log_stream_enable=self.data.get("lts_attack_log_stream_enable"),
            lts_access_log_stream_id=access_log_stream_id,
            lts_access_log_stream_enable=self.data.get("lts_access_log_stream_enable"),
            lts_flow_log_stream_id=flow_log_stream_id,
            lts_flow_log_stream_enable=self.data.get("lts_flow_log_stream_enable"),
        )
        return request

    def perform_action(self, resource):
        return super().perform_action(resource)


@Cfw.filter_registry.register("check-firewall-acl")
class NoAclFirewallFilter(Filter):
    """Filter firewall without acl .

        :example:

        .. code-block:: yaml

            policies:
              - name: query-firewall-without-acl.
                resource: huaweicloud.cfw
                filters:
                  - type: check-firewall-acl
        """
    schema = type_schema('check-firewall-acl')

    def process(self, resources, event=None):
        client = self.manager.get_client()
        acl = []
        object_id = ""

        for record in resources:
            firewall = record.get('data').get('records')[0]
            protect_objects = firewall.get('protect_objects')

            if protect_objects is not None:
                for p in protect_objects:
                    obj_id = p.get('object_id')
                    # protect type: 0 (north-south), 1 (east-west)
                    # only filter north-south protect object
                    type = p.get('type')
                    if obj_id is not None and type == 0:
                        object_id = obj_id

            try:
                request = ListAclRulesRequest(
                    object_id=object_id,
                    limit=DEFAULT_LIMIT_SIZE,
                    offset=0
                )
                response = client.list_acl_rules(request)
                log.info("[filters]-{check-firewall-acl} "
                         "The resource:[cfw] with request:[%s] "
                         "query acl list is success.", request)
                r = response.data.records

                if r is None or len(r) == 0:
                    acl.append(object_id)
            except exceptions.ClientRequestException as e:
                log.error("[filters]-{check-firewall-acl} "
                          "The resource:[cfw] with request:[%s] "
                          "query acl list is failed, cause: "
                          "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                          request, e.status_code, e.request_id, e.error_code, e.error_msg)
                raise e

        return acl


@Cfw.action_registry.register("create-default-acl-rule")
class CreateDefaultAclRules(HuaweiCloudBaseAction):
    """Action to create default ACL rule,This default ACL is a rule named "deny-all"
    that blocks all network traffic. It applies to any source (0.0.0.0/0) and any
    destination (0.0.0.0/0), covering all IP protocols and all port ranges (1-65535).
    The rule direction is inbound and is always pinned at the bottom. parameter
    status, which is used to determine whether a rule is enabled.
         :example:

         .. code-block:: yaml

             policies:
               - name: cfw-create-tags
                 resource: huaweicloud.cfw
                 actions:
                    - type: create-default-acl-rule
                        status: 0                       # 0: disable; 1: enable

         """
    schema = type_schema('create-default-acl-rule',
                         required=["status"],
                         status={'type': 'integer', 'default': 0})

    def process(self, resources):
        client = self.manager.get_client()

        for record in resources:
            firewall = record.get('data').get('records')[0]
            protect_objects = firewall.get('protect_objects')
            try:
                # get object id
                if protect_objects is not None:
                    for p in protect_objects:
                        obj_id = p.get('object_id')
                        type = p.get('type')
                        if obj_id is not None and type == 0:
                            request = self.init_request(obj_id)
                            client.add_acl_rule(request)
                            log.info("[actions]-{create-default-acl-rule} "
                                     "The resource:[cfw] with request:[%s] "
                                     "create default acl rule is success.", request)
            except exceptions.ClientRequestException as e:
                log.error("[actions]-{create-default-acl-rule} "
                          "The resource:[cfw] with request:[%s] "
                          "create default acl rule is failed, cause: "
                          "status_code[%s] request_id[%s] error_code[%s] error_msg[%s]",
                          request, e.status_code, e.request_id, e.error_code, e.error_msg)
                raise

    def init_request(self, object_id, *args):
        request = AddAclRuleRequest()
        serviceRules = RuleServiceDto(
            type=0,
            protocol=-1,
            source_port="1-65535",
            dest_port="1-65535"
        )
        destinationRules = RuleAddressDtoForRequest(
            type=0,
            address="0.0.0.0/0"
        )
        sourceRules = RuleAddressDtoForRequest(
            type=0,
            address="0.0.0.0/0"
        )
        sequenceRules = OrderRuleAclDto(
            bottom=1
        )
        listRulesbody = [
            AddRuleAclDtoRules(
                name="deny-all",
                sequence=sequenceRules,
                address_type=0,
                action_type=1,
                status=self.data.get("status"),
                long_connect_enable=0,
                direction=0,
                source=sourceRules,
                destination=destinationRules,
                service=serviceRules
            )
        ]
        request.body = AddRuleAclDto(
            rules=listRulesbody,
            type=0,
            object_id=object_id
        )
        return request

    def perform_action(self, resource):
        return super().perform_action(resource)
