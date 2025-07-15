from huaweicloud_common import BaseTest


class CfwTest(BaseTest):


    def test_firewall_list_query(self):
        factory = self.replay_flight_data("cfw_query")
        p = self.load_policy({
            "name": "query_cloud_firewall",
            "resource": "huaweicloud.cfw"},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 4)

    def test_cfw_eip_filter(self):
        factory = self.replay_flight_data("cfw_eip_filter")
        p = self.load_policy(
            {
                "name": "protect-cfw-eip",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-unprotected-eip"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cfw_eip_protect_action(self):
        factory = self.replay_flight_data("cfw_eip_protect_action")
        p = self.load_policy(
            {
                "name": "protect-cfw-eip",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-unprotected-eip",
                }],
                "actions": [{
                "type": "protect-eip",
                "fwInstanceId": "f2bd4277-d2b4-40f3-b98d-75ecc51c68de"
            }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cfw_tags_filter(self):
        factory = self.replay_flight_data("cfw_tagged_filter")
        p = self.load_policy(
            {
                "name": "cfw_tagged",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-untagged-firewall"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 3)

    def test_cfw_create_tags_action(self):
        factory = self.replay_flight_data("cfw_create_tags_action")
        p = self.load_policy(
            {
                "name": "cfw-create-tags",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-untagged-firewall",
                }],
                "actions": [{
                "type": "create-tags",
                "tag_infos": [
                    {"fw_instance_ids":  ["a82b5c38-aee4-4a68-8186-c09975868db9"],
                     "tags": [{"key": "env", "value": "dev"}]}
                ],
                "default_tags": [{"key": "env", "value": "prod"}]
            }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cfw_alarm_config_filter(self):
        factory = self.replay_flight_data("cfw_alarm_config_filter")
        p = self.load_policy(
            {
                "name": "cfw_alarm_config",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-alarm-config",
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
                    "type": "check-alarm-config",
                    "alarm_types": ['attack','traffic threshold crossing','EIP unprotected','threat intelligence']
                }],
                "actions": [{
                "type": "update-alarm-config",
                "alarm_time_period": 1,
                "frequency_count": 10,
                "frequency_time": 10,
                "severity": "CRITICAL,HIGH,MEDIUM,LOW",
                "topic_urn": "urn:smn:ap-southeast-3:08990bb558904dd8ba065ba082af538d:test",
                "username": "w3_sso_z30000215/h00934445"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 4)

    def test_cfw_logged_filter(self):
        factory = self.replay_flight_data("cfw_logged_filter")
        p = self.load_policy(
            {
                "name": "check-unlogged-firewall",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-unlogged-firewall"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cfw_logged_config_update_action(self):
        factory = self.replay_flight_data("cfw_log_config_update_action")
        p = self.load_policy(
            {
                "name": "cfw_logged",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-unlogged-firewall"
                }],
                "actions": [{
                "type": "update-log-config",
                 "lts_log_group_id": "9e2b6f24-09f3-4acc-a0a9-b9a2e26dffef"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 3)

    def test_cfw_acl_filter(self):
        factory = self.replay_flight_data("cfw_no_acl_filter")
        p = self.load_policy(
            {
                "name": "cfw-check-firewall-acl",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-firewall-acl"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cfw_create_default_acl_rule_action(self):
        factory = self.replay_flight_data("create_default_acl_rule_action")
        p = self.load_policy(
            {
                "name": "cfw_acl_action",
                "resource": "huaweicloud.cfw",
                "filters": [{
                    "type": "check-firewall-acl"
                }],
                "actions": [{
                "type": "create-default-acl-rule"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)