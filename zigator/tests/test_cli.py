#!/usr/bin/env python3

# Copyright (C) 2020 Dimitrios-Georgios Akestoridis
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

import contextlib
import io
import re
import unittest
import zigator


class TestCLI(unittest.TestCase):
    def test_zigator(self):
        """Test the default message."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            zigator.main(["zigator"])
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertGreater(len(captured_output), 14)
        self.assertEqual(captured_output[:14], "usage: zigator")

    def test_zigator_help_short(self):
        """Test the -h argument."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            with self.assertRaises(SystemExit) as cm:
                zigator.main(["zigator", "-h"])
        self.assertEqual(str(cm.exception), "0")
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertGreater(len(captured_output), 14)
        self.assertEqual(captured_output[:14], "usage: zigator")

    def test_zigator_help_long(self):
        """Test the --help argument."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            with self.assertRaises(SystemExit) as cm:
                zigator.main(["zigator", "--help"])
        self.assertEqual(str(cm.exception), "0")
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertGreater(len(captured_output), 14)
        self.assertEqual(captured_output[:14], "usage: zigator")

    def test_zigator_version_short(self):
        """Test the -v argument."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            with self.assertRaises(SystemExit) as cm:
                zigator.main(["zigator", "-v"])
        self.assertEqual(str(cm.exception), "0")
        captured_output = tmp_stdout.getvalue().rstrip()
        match = re.search(
            r"^(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            captured_output)
        self.assertIsNotNone(match)

    def test_zigator_version_long(self):
        """Test the --version argument."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            with self.assertRaises(SystemExit) as cm:
                zigator.main(["zigator", "--version"])
        self.assertEqual(str(cm.exception), "0")
        captured_output = tmp_stdout.getvalue().rstrip()
        match = re.search(
            r"^(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            captured_output)
        self.assertIsNotNone(match)

    def test_zigator_debug_short(self):
        """Test the -d argument."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            zigator.main(["zigator", "-d"])
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertGreater(len(captured_output), 14)
        self.assertEqual(captured_output[:14], "usage: zigator")

    def test_zigator_debug_long(self):
        """Test the --debug argument."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            zigator.main(["zigator", "--debug"])
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertGreater(len(captured_output), 14)
        self.assertEqual(captured_output[:14], "usage: zigator")

    def test_none_arguments(self):
        """Test the usage of None for the list of arguments."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            zigator.main(None)
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertGreater(len(captured_output), 14)
        self.assertEqual(captured_output[:14], "usage: zigator")

    def test_unrecognized_argument_short(self):
        """Test the usage of a short unrecognized argument."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stderr(tmp_stdout):
            with self.assertRaises(SystemExit) as cm:
                zigator.main(["zigator", "-o"])
        self.assertEqual(str(cm.exception), "2")
        captured_error = tmp_stdout.getvalue().rstrip()
        self.assertGreater(len(captured_error), 14)
        self.assertEqual(captured_error[:14], "usage: zigator")

    def test_unrecognized_argument_long(self):
        """Test the usage of a long unrecognized argument."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stderr(tmp_stdout):
            with self.assertRaises(SystemExit) as cm:
                zigator.main(["zigator", "--output"])
        self.assertEqual(str(cm.exception), "2")
        captured_error = tmp_stdout.getvalue().rstrip()
        self.assertGreater(len(captured_error), 14)
        self.assertEqual(captured_error[:14], "usage: zigator")


if __name__ == "__main__":
    unittest.main()
