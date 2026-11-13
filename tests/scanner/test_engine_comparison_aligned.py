"""Aligned-source and NodeGoat experiment fixture regression checks."""

import unittest

from validation.engine_comparison.run_aligned import (
    ALIAS, COMMAND_QUERY, CONTROLS, EXTENDED_CASES, NODEGOAT_SHA,
    NOSQL_QUERY,
)


class AlignedExperimentTests(unittest.TestCase):
    def test_existing_cases_preserved_with_alias_added_separately(self):
        self.assertEqual(len(EXTENDED_CASES), 10)
        self.assertEqual(EXTENDED_CASES["alias_destructured"], (ALIAS.name, True))
        self.assertTrue(ALIAS.is_file())

    def test_command_query_uses_field_sources_and_module_sinks(self):
        query = COMMAND_QUERY.read_text(encoding="utf-8")
        self.assertIn('getAPropertyRead("body").getAPropertyRead("command")', query)
        self.assertIn('getAPropertyRead("query").getAPropertyRead("command")', query)
        self.assertIn('moduleMember("child_process", "exec")', query)
        self.assertIn('moduleMember("child_process", "execSync")', query)
        self.assertNotIn('source = DataFlow::parameterNode(p)\n', query)

    def test_nosql_query_requires_where_object_to_reach_find(self):
        query = NOSQL_QUERY.read_text(encoding="utf-8")
        self.assertIn('getAPropertyRead("query").getAPropertyRead("threshold")', query)
        self.assertIn('getPropertyByName("$where")', query)
        self.assertIn('WhereObjectToFind::flow', query)

    def test_controls_cover_vulnerable_fixed_numeric_and_unrelated(self):
        self.assertEqual(NODEGOAT_SHA, "c5cb68a7084e4ae7dcc60e6a98768720a81841e8")
        for relative in ("vulnerable/route.js", "vulnerable/dao.js", "safe_fixed.js",
                         "safe_numeric.js", "unrelated_object.js"):
            self.assertTrue((CONTROLS / relative).is_file(), relative)


if __name__ == "__main__":
    unittest.main()
