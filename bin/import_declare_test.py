#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import os
import sys
import warnings

warnings.filterwarnings("ignore")

BINDIR = os.path.dirname(os.path.realpath(os.path.dirname(__file__)))
LIBDIR = os.path.join(BINDIR, "lib")
LIBDIR_TP_ROOT_DIR = os.path.join(LIBDIR, "3rdparty")

if sys.platform.startswith("win32"):
    PLATFORM_DIR = "windows_x86_64"
elif sys.platform.startswith("darwin"):
    PLATFORM_DIR = "darwin_x86_64"
else:
    PLATFORM_DIR = "linux_x86_64"

TPDIR = os.path.join(
    LIBDIR_TP_ROOT_DIR,
    PLATFORM_DIR,
    f"python{sys.version_info.major}{sys.version_info.minor}",
)

import_override = [TPDIR, LIBDIR]

sys.path = import_override + sys.path

ta_name = "Splunk_TA_MS_Security"
