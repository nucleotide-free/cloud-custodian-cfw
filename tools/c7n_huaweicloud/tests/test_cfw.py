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

    # def test_cfw_eip_query(self):
    #     factory = self.replay_flight_data("cfw_cfw_eip_query")
    #     p = self.load_policy(
    #         {"name": "list_eips", "resource": "huaweicloud.cfw-eip"},
    #         session_factory=factory,
    #     )
    #     resources = p.run()
    #     self.assertEqual(len(resources), 4)

    def test_cfw_eip_filter(self):
        factory = self.replay_flight_data("cfw_cfw_eip_filter")
        p = self.load_policy(
            {
                "name": "protect-cfw-eip",
                "resource": "huaweicloud.cfw-firewall",
                "filters": [{
                    "type": "eip-unprotected"
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cfw_eip_protect_action(self):
        factory = self.replay_flight_data("cfw_eip_protect")
        p = self.load_policy(
            {
                "name": "protect-cfw-eip",
                "resource": "huaweicloud.cfw-firewall",
                "filters": [{
                    "type": "eip-unprotected",
                }],
                "actions": [{
                "type": "protect-eip",
                "fwInstanceId": "d06dad70-b3be-4480-86bc-b3d139e9938b"
            }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
