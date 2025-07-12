from huaweicloud_common import BaseTest


class CfwTest(BaseTest):


    def test_firewall_list_query(self):
        factory = self.replay_flight_data("cfw_query")
        p = self.load_policy(
            {"name": "list_firewall_list", "resource": "huaweicloud.cfw"},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 4)

    def test_firewall_detail_query(self):
        factory = self.replay_flight_data("cfw_firewall_detail_query")
        p = self.load_policy(
            {"name": "list_firewall_detail", "resource": "huaweicloud.cfw-firewall"},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 4)

    def test_cfw_eip_filter(self):
        factory = self.replay_flight_data("cfw_cfw_eip_filter")
        p = self.load_policy(
            {
                "name": "protect-cfw-eip",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "eip-unprotected"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)


    def test_cfw_tags_filter(self):
        factory = self.replay_flight_data("cfw_cfw_tagged_filter")
        p = self.load_policy(
            {
                "name": "cfw_tagged",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "firewall-untagged"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 3)

    def test_cfw_logged_filter(self):
        factory = self.replay_flight_data("cfw_logged_filter")
        p = self.load_policy(
            {
                "name": "cfw_logged",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "firewall-logged"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 0)

    def test_cfw_alarm_config_filter(self):
        factory = self.replay_flight_data("cfw_alarm_config_filter")
        p = self.load_policy(
            {
                "name": "cfw_alarm_config",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "alarm-config-check",
                    "alarm_types": ['attack','traffic threshold crossing','EIP unprotected','threat intelligence']
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 4)

    def test_cfw_alarm_config_update_action(self):
        factory = self.replay_flight_data("cfw_alarm_config_update_action")
        p = self.load_policy(
            {
                "name": "cfw_alarm_config_update",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "alarm-config-check",
                    "alarm_types": ['attack','traffic threshold crossing','EIP unprotected','threat intelligence']
                }],
                "actions": [{
                "type": "update-firewall-alarm-config",
                "alarm_types": ['attack'],
                "alarm_time_period": 1,
                "frequency_count": 10,
                "frequency_time": 10,
                "severity": "CRITICAL,HIGH,MEDIUM,LOW",
                "topic_urn": "urn:smn:cn-east-3:28f403ddd3f141daa6e046e85cb15519:wt_test",
                "username": "w3_sso_z30000215/h00934445",
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 4)


    def test_cfw_eip_protect_action(self):
        factory = self.replay_flight_data("cfw_eip_protect")
        p = self.load_policy(
            {
                "name": "protect-cfw-eip",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "eip-unprotected",
                }],
                "actions": [{
                "type": "protect-eip",
                "fwInstanceId": "0cf6f7a8-a062-455c-a5ac-1f2af9272af6"
            }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cfw_create_tags_action(self):
        factory = self.replay_flight_data("cfw_create_tags")
        p = self.load_policy(
            {
                "name": "cfw-create-tags",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "firewall-untagged",
                }],
                "actions": [{
                "type": "create-tags",
                "tag_infos": [
                    {"fw_instance_ids":  ["f2bd4277-d2b4-40f3-b98d-75ecc51c68de", "d06dad70-b3be-4480-86bc-b3d139e9938b", "89d537d1-2ca9-4ec6-b822-8c524628e666"],
                     "tags": [{"key": "env", "value": "dev"}]}
                ]
            }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
