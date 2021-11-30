#!/usr/bin/env python3

# Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis
#
# This file is part of Zigator.
#
# Zigator is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# Zigator is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Zigator. If not, see <https://www.gnu.org/licenses/>.

import subprocess
import unittest


class TestEntryPoint(unittest.TestCase):
    def test_which_zigator(self):
        """Test whether the zigator command can be located or not."""
        cp = subprocess.run(
            ["which", "zigator"],
            capture_output=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 0)

    def test_zigator_version(self):
        """Test displaying the version of Zigator."""
        cp = subprocess.run(
            ["zigator", "-v"],
            capture_output=True,
            check=False,
        )
        self.assertEqual(cp.returncode, 0)
        self.assertRegex(
            cp.stdout.decode().rstrip(),
            r"^(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
        )


if __name__ == "__main__":
    unittest.main()
