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

from .enc_nwk_cmd import enc_nwk_cmd


def main(train_type, db_filepath, out_dirpath, seed, restricted):
    """Train a classifier from data stored in a database file."""
    if train_type.lower() == "enc-nwk-cmd":
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-nwk-cmd"),
                    seed,
                    restricted,
                    single_cmd=None)
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-routerequest"),
                    seed,
                    restricted,
                    single_cmd="NWK Route Request")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-routereply"),
                    seed,
                    restricted,
                    single_cmd="NWK Route Reply")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-networkstatus"),
                    seed,
                    restricted,
                    single_cmd="NWK Network Status")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-leave"),
                    seed,
                    restricted,
                    single_cmd="NWK Leave")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-routerecord"),
                    seed,
                    restricted,
                    single_cmd="NWK Route Record")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-rejoinreq"),
                    seed,
                    restricted,
                    single_cmd="NWK Rejoin Request")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-rejoinrsp"),
                    seed,
                    restricted,
                    single_cmd="NWK Rejoin Response")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-linkstatus"),
                    seed,
                    restricted,
                    single_cmd="NWK Link Status")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-networkreport"),
                    seed,
                    restricted,
                    single_cmd="NWK Network Report")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-networkupdate"),
                    seed,
                    restricted,
                    single_cmd="NWK Network Update")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-edtimeoutreq"),
                    seed,
                    restricted,
                    single_cmd="NWK End Device Timeout Request")
        enc_nwk_cmd(db_filepath,
                    os.path.join(out_dirpath, "enc-edtimeoutrsp"),
                    seed,
                    restricted,
                    single_cmd="NWK End Device Timeout Response")
    else:
        raise ValueError("Unknown training type \"{}\"".format(train_type))
