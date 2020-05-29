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

"""
Derivation of the version number for the zigator package
"""

import os
import re
import subprocess


def getversion(pkg_dirpath):
    version_filepath = os.path.join(pkg_dirpath, "VERSION.txt")
    git_dirpath = os.path.join(os.path.dirname(pkg_dirpath), ".git")
    try:
        cmd = "git --git-dir {} describe --tags".format(git_dirpath)
        cp = subprocess.run(
            cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if cp.returncode == 0:
            match = re.search(
                r"^v([0-9]+\.[0-9]+)(\-[0-9]+\-g[0-9a-f]{7})?$",
                cp.stdout.decode().rstrip())
            if match:
                version = match.group(1)
                if match.group(2) is not None:
                    version += "+" + re.search(
                        r"^\-[0-9]+\-g([0-9a-f]{7})$",
                        match.group(2)).group(1)
                with open(version_filepath, "w") as fp:
                    fp.write("{}\n".format(version))
                return version

        cmd = "git --git-dir {} rev-parse --short HEAD".format(git_dirpath)
        cp = subprocess.run(
            cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if cp.returncode == 0:
            match = re.search(r"^[0-9a-f]{7}$", cp.stdout.decode().rstrip())
            if match:
                version = "0+" + match.group(0)
                with open(version_filepath, "w") as fp:
                    fp.write("{}\n".format(version))
                return version
    except Exception:
        pass

    if os.path.isfile(version_filepath):
        with open(version_filepath, "r") as fp:
            match = re.search(
                r"^(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
                fp.read().rstrip())
        if match:
            return match.group(0)

    match = re.search(r"tag: v([0-9]+\.[0-9]+)(,|$)", "$Format:%D$")
    if match:
        return match.group(1)

    match = re.search(r"^[0-9a-f]{7}$", "$Format:%h$")
    if match:
        return "0+" + match.group(0)

    return "0+unknown"
