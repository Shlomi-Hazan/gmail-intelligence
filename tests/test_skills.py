"""Structure checks for the project Skills (.claude/skills/<name>/SKILL.md)."""
import re
import unittest
from pathlib import Path

SKILLS = Path(__file__).resolve().parent.parent / ".claude" / "skills"
EXPECTED = {"gmail-project-status", "gmail-project-check", "gmail-security-review", "gmail-milestone-workflow"}
FUTURE_OPERATIONAL = ("gmail-audit", "gmail-classify", "gmail-cleanup-preview",
                      "gmail-execute", "gmail-organize", "gmail-maintain")


class SkillTests(unittest.TestCase):
    def test_expected_skills_exist_with_valid_frontmatter(self):
        found = {p.parent.name for p in SKILLS.glob("*/SKILL.md")}
        self.assertEqual(found, EXPECTED)
        for name in EXPECTED:
            text = (SKILLS / name / "SKILL.md").read_text()
            m = re.match(r"---\nname: (\S+)\ndescription: (.+)\n(?:allowed-tools: .+\n)?---\n", text)
            self.assertIsNotNone(m, name)
            self.assertEqual(m.group(1), name)
            self.assertGreater(len(m.group(2)), 40)
            self.assertGreater(len(text.split("---", 2)[2].strip()), 100)

    def test_no_future_operational_skills_yet(self):
        for name in FUTURE_OPERATIONAL:
            self.assertFalse((SKILLS / name).exists(), name)

    def test_skills_grant_no_write_or_network_tools(self):
        for name in EXPECTED:
            text = (SKILLS / name / "SKILL.md").read_text()
            tools = re.search(r"allowed-tools: (.+)", text).group(1)
            for banned in ("Write", "Edit", "WebFetch", "WebSearch", "git push", "git commit",
                           "gh pr merge", "gh pr create", "gh issue close"):
                self.assertNotIn(banned, tools, f"{name} allows {banned}")


if __name__ == "__main__":
    unittest.main()
