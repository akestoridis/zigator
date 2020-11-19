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

import logging
import os

import graphviz
import numpy as np
from sklearn import metrics
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import export_graphviz
from sklearn.tree import export_text

from .. import config


def enc_nwk_cmd(db_filepath, out_dirpath, seed, restricted, single_cmd=None):
    """Train a classifier to distinguish encrypted NWK commands."""
    # Sanity check
    if not os.path.isfile(db_filepath):
        raise ValueError("The provided database file \"{}\" "
                         "does not exist".format(db_filepath))

    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Connect to the provided database
    config.db.connect(db_filepath)

    # Fetch all encrypted NWK commands
    columns = [
        "pcap_directory",
        "pcap_filename",
        "pkt_num",
        "pkt_time",
        "phy_length",
        "mac_fcs",
        "mac_frametype",
        "mac_security",
        "mac_framepending",
        "mac_ackreq",
        "mac_panidcomp",
        "mac_dstaddrmode",
        "mac_frameversion",
        "mac_srcaddrmode",
        "mac_seqnum",
        "mac_dstpanid",
        "mac_dstshortaddr",
        "mac_dstextendedaddr",
        "mac_srcpanid",
        "mac_srcshortaddr",
        "mac_srcextendedaddr",
        "nwk_frametype",
        "nwk_protocolversion",
        "nwk_discroute",
        "nwk_multicast",
        "nwk_security",
        "nwk_srcroute",
        "nwk_extendeddst",
        "nwk_extendedsrc",
        "nwk_edinitiator",
        "nwk_dstshortaddr",
        "nwk_srcshortaddr",
        "nwk_radius",
        "nwk_seqnum",
        "nwk_dstextendedaddr",
        "nwk_srcextendedaddr",
        "nwk_srcroute_relaycount",
        "nwk_srcroute_relayindex",
        "nwk_srcroute_relaylist",
        "nwk_aux_seclevel",
        "nwk_aux_keytype",
        "nwk_aux_extnonce",
        "nwk_aux_framecounter",
        "nwk_aux_srcaddr",
        "nwk_aux_keyseqnum",
        "nwk_cmd_payloadlength",
        "der_same_macnwkdst",
        "der_same_macnwksrc",
        "der_mac_dsttype",
        "der_mac_srctype",
        "der_nwk_dsttype",
        "der_nwk_srctype",
        "nwk_cmd_id",
    ]
    conditions = [
        ("error_msg", None),
        ("nwk_frametype", "0b01: NWK Command"),
        ("nwk_security", "0b1: NWK Security Enabled"),
        ("!nwk_cmd_id", None),
    ]
    raw_samples = config.db.fetch_values(columns, conditions, False)
    logging.info("Fetched {} raw samples of encrypted NWK commands"
                 "".format(len(raw_samples)))

    # Write the raw samples in a file
    if single_cmd is None:
        fp = open(os.path.join(out_dirpath, "raw-samples.tsv"), "w")
        fp.write("#{}\n".format("\t".join(columns)))
        for raw_sample in raw_samples:
            fp.write("{}\n".format("\t".join([str(x) for x in raw_sample])))
        fp.close()

    # Map each NWK command to an integer value
    nwk_commands = {
        "0x01: NWK Route Request": 1,
        "0x02: NWK Route Reply": 2,
        "0x03: NWK Network Status": 3,
        "0x04: NWK Leave": 4,
        "0x05: NWK Route Record": 5,
        "0x06: NWK Rejoin Request": 6,
        "0x07: NWK Rejoin Response": 7,
        "0x08: NWK Link Status": 8,
        "0x09: NWK Network Report": 9,
        "0x0a: NWK Network Update": 10,
        "0x0b: NWK End Device Timeout Request": 11,
        "0x0c: NWK End Device Timeout Response": 12,
    }
    if single_cmd is None:
        class_names = sorted(list(nwk_commands.keys()), key=nwk_commands.get)
    elif single_cmd not in nwk_commands.keys():
        raise ValueError("Unknown NWK command \"{}\"".format(single_cmd))
    else:
        class_names = ["Other NWK Command", single_cmd]
    logging.info("The classifier will be trained to distinguish "
                 "{} NWK commands".format(len(class_names)))

    # Define the features that the classifier will use
    if restricted:
        feature_definitions = [
            ("nwk_cmd_payloadlength", "NUMERICAL"),
            ("nwk_radius", "NUMERICAL"),
            ("der_nwk_dsttype", "CATEGORICAL"),
            ("der_nwk_srctype", "CATEGORICAL"),
            ("der_same_macnwkdst", "CATEGORICAL"),
            ("der_same_macnwksrc", "CATEGORICAL"),
        ]
    else:
        feature_definitions = [
            ("phy_length", "NUMERICAL"),
            # "mac_fcs",
            ("mac_frametype", "CATEGORICAL"),
            ("mac_security", "CATEGORICAL"),
            ("mac_framepending", "CATEGORICAL"),
            ("mac_ackreq", "CATEGORICAL"),
            ("mac_panidcomp", "CATEGORICAL"),
            ("mac_dstaddrmode", "CATEGORICAL"),
            ("mac_frameversion", "CATEGORICAL"),
            ("mac_srcaddrmode", "CATEGORICAL"),
            # "mac_seqnum",
            # "mac_dstpanid",
            # "mac_dstshortaddr",
            # "mac_dstextendedaddr",
            # "mac_srcpanid"
            # "mac_srcshortaddr",
            # "mac_srcextendedaddr",
            ("nwk_frametype", "CATEGORICAL"),
            ("nwk_protocolversion", "CATEGORICAL"),
            ("nwk_discroute", "CATEGORICAL"),
            ("nwk_multicast", "CATEGORICAL"),
            ("nwk_security", "CATEGORICAL"),
            ("nwk_srcroute", "CATEGORICAL"),
            ("nwk_extendeddst", "CATEGORICAL"),
            ("nwk_extendedsrc", "CATEGORICAL"),
            ("nwk_edinitiator", "CATEGORICAL"),
            # "nwk_dstshortaddr",
            # "nwk_srcshortaddr",
            ("nwk_radius", "NUMERICAL"),
            # "nwk_seqnum",
            # "nwk_dstextendedaddr",
            # "nwk_srcextendedaddr",
            # [Multicast Control field (0/1 byte)]
            # "nwk_srcroute_relaycount",
            # "nwk_srcroute_relayindex",
            # "nwk_srcroute_relaylist",
            ("nwk_aux_seclevel", "CATEGORICAL"),
            ("nwk_aux_keytype", "CATEGORICAL"),
            ("nwk_aux_extnonce", "CATEGORICAL"),
            # "nwk_aux_framecounter",
            # "nwk_aux_srcaddr",
            # "nwk_aux_keyseqnum",
            ("nwk_cmd_payloadlength", "NUMERICAL"),
            ("der_same_macnwkdst", "CATEGORICAL"),
            ("der_same_macnwksrc", "CATEGORICAL"),
            ("der_mac_dsttype", "CATEGORICAL"),
            ("der_mac_srctype", "CATEGORICAL"),
            ("der_nwk_dsttype", "CATEGORICAL"),
            ("der_nwk_srctype", "CATEGORICAL"),
        ]
    logging.info("The classifier will use {} unencoded features"
                 "".format(len(feature_definitions)))

    # Process the raw samples
    numerical_table = []
    categorical_table = []
    dataset_labels = []
    for raw_sample in raw_samples:
        # Process the features
        numerical_row = []
        categorical_row = []
        for feature_definition in feature_definitions:
            # Get the name and type of the feature
            feature_name = feature_definition[0]
            feature_type = feature_definition[1]

            # Sanity check
            if feature_name not in columns:
                raise ValueError("Unknown feature name \"{}\""
                                 "".format(feature_name))

            # Extract the value of the feature
            value = raw_sample[columns.index(feature_name)]

            # Sanity checks
            if feature_name == "mac_dstpanid" and value is None:
                raise ValueError("Missing the destination PAN ID")
            elif feature_name == "mac_dstshortaddr" and value is None:
                raise ValueError("Missing the MAC destination short address")
            elif feature_name == "mac_srcshortaddr" and value is None:
                raise ValueError("Missing the MAC source short address")
            elif feature_name == "nwk_dstshortaddr" and value is None:
                raise ValueError("Missing the NWK destination short address")
            elif feature_name == "nwk_srcshortaddr" and value is None:
                raise ValueError("Missing the NWK source short address")
            elif feature_name == "nwk_aux_srcaddr" and value is None:
                raise ValueError("Missing the NWKAUX source extended address")
            elif (feature_name == "der_mac_dsttype"
                    and value == "MAC Dst Type: None"):
                raise ValueError("Unknown MAC destination type")
            elif (feature_name == "der_mac_dsttype"
                    and value == "MAC Dst Type: Conflicting Data"):
                raise ValueError("Conflicting MAC destination type")
            elif (feature_name == "der_mac_srctype"
                    and value == "MAC Src Type: None"):
                raise ValueError("Unknown MAC source type")
            elif (feature_name == "der_mac_srctype"
                    and value == "MAC Src Type: Conflicting Data"):
                raise ValueError("Conflicting MAC source type")
            elif (feature_name == "der_nwk_dsttype"
                    and value == "NWK Dst Type: None"):
                raise ValueError("Unknown NWK destination type")
            elif (feature_name == "der_nwk_dsttype"
                    and value == "NWK Dst Type: Conflicting Data"):
                raise ValueError("Conflicting NWK destination type")
            elif (feature_name == "der_nwk_srctype"
                    and value == "NWK Src Type: None"):
                raise ValueError("Unknown NWK source type")
            elif (feature_name == "der_nwk_srctype"
                    and value == "NWK Src Type: Conflicting Data"):
                raise ValueError("Conflicting NWK source type")

            # Separate numerical features from categorical features
            if feature_type == "NUMERICAL":
                numerical_row.append(value)
            elif feature_type == "CATEGORICAL":
                categorical_row.append(value)
            else:
                raise ValueError("Unknown feature type \"{}\""
                                 "".format(feature_type))
        numerical_table.append(numerical_row)
        categorical_table.append(categorical_row)

        # Generate the labels of the dataset
        label = nwk_commands.get(raw_sample[-1], None)
        if label is None:
            raise ValueError("Unknown NWK command \"{}\""
                             "".format(raw_sample[-1]))
        elif single_cmd is not None:
            if label == nwk_commands.get(single_cmd, None):
                dataset_labels.append(1)
            else:
                dataset_labels.append(0)
        else:
            dataset_labels.append(label)

    # Use one-hot encoding for the categorical features
    enc = OneHotEncoder(sparse=False)
    encoded_table = enc.fit_transform(categorical_table)
    encoded_features = enc.get_feature_names()

    # Generate the table and the features of the dataset
    dataset_table = np.concatenate(
        (np.array(numerical_table), np.array(encoded_table)),
        axis=1)
    dataset_features = (
        [fd[0] for fd in feature_definitions if fd[1] == "NUMERICAL"]
        + enc.get_feature_names().tolist()
    )
    logging.info("The classifier will use {} encoded features"
                 "".format(len(dataset_features)))

    # Write the features of the dataset in a file
    with open(os.path.join(out_dirpath, "dataset-features.tsv"), "w") as fp:
        fp.write("\n".join(dataset_features))

    # Compute some statistics about the unique samples of the dataset
    if single_cmd is None:
        unique_samples = np.unique(dataset_table, axis=0)
        cmd_counters = {cmd_id: [] for cmd_id in nwk_commands.values()}
        overlapping = []
        for unique_sample in unique_samples:
            # Get the indices of each unique sample in the dataset
            indices = (dataset_table == (unique_sample)).all(axis=1).nonzero()

            # Compute the frequency of each NWK command per unique sample
            cmd_frequency = {cmd_id: 0 for cmd_id in nwk_commands.values()}
            for index in indices[0]:
                cmd_frequency[dataset_labels[index]] += 1

            # Update the counters of each NWK command
            for cmd_id in nwk_commands.values():
                if cmd_frequency[cmd_id] > 0:
                    cmd_counters[cmd_id].append((unique_sample.tolist(),
                                                 cmd_frequency[cmd_id]))

            # Check whether this sample applies to multiple NWK commands
            matching_cmds = [cmd_name for cmd_name in class_names
                             if cmd_frequency[nwk_commands[cmd_name]] > 0]
            if len(matching_cmds) > 1:
                overlapping.append((matching_cmds,
                                    unique_sample.tolist()))
        cmd_filepaths = {
            "0x01: NWK Route Request": (
                os.path.join(out_dirpath, "unique-routerequest-samples.tsv")
            ),
            "0x02: NWK Route Reply": (
                os.path.join(out_dirpath, "unique-routereply-samples.tsv")
            ),
            "0x03: NWK Network Status": (
                os.path.join(out_dirpath, "unique-networkstatus-samples.tsv")
            ),
            "0x04: NWK Leave": (
                os.path.join(out_dirpath, "unique-leave-samples.tsv")
            ),
            "0x05: NWK Route Record": (
                os.path.join(out_dirpath, "unique-routerecord-samples.tsv")
            ),
            "0x06: NWK Rejoin Request": (
                os.path.join(out_dirpath, "unique-rejoinreq-samples.tsv")
            ),
            "0x07: NWK Rejoin Response": (
                os.path.join(out_dirpath, "unique-rejoinrsp-samples.tsv")
            ),
            "0x08: NWK Link Status": (
                os.path.join(out_dirpath, "unique-linkstatus-samples.tsv")
            ),
            "0x09: NWK Network Report": (
                os.path.join(out_dirpath, "unique-networkreport-samples.tsv")
            ),
            "0x0a: NWK Network Update": (
                os.path.join(out_dirpath, "unique-networkupdate-samples.tsv")
            ),
            "0x0b: NWK End Device Timeout Request": (
                os.path.join(out_dirpath, "unique-edtimeoutreq-samples.tsv")
            ),
            "0x0c: NWK End Device Timeout Response": (
                os.path.join(out_dirpath, "unique-edtimeoutrsp-samples.tsv")
            ),
        }
        for cmd_name in class_names:
            with open(cmd_filepaths[cmd_name], "w") as fp:
                for cmd_counter in cmd_counters[nwk_commands[cmd_name]]:
                    fp.write("{}\t{}\n"
                             "".format(cmd_counter[0], cmd_counter[1]))
        fp = open(os.path.join(out_dirpath, "overlapping-samples.tsv"), "w")
        for overlap in overlapping:
            fp.write("{}\t{}\n".format(overlap[0], overlap[1]))
        fp.close()
        fp = open(os.path.join(out_dirpath, "num-unique-samples.tsv"), "w")
        for cmd_name in class_names:
            fp.write("{}\t{}\n"
                     "".format(cmd_name,
                               len(cmd_counters[nwk_commands[cmd_name]])))
        fp.close()

    # Split the dataset into a training set and a testing set
    training_table, testing_table, training_labels, testing_labels = (
        train_test_split(dataset_table,
                         dataset_labels,
                         test_size=0.2,
                         random_state=seed,
                         shuffle=True)
    )
    logging.info("Split the dataset into {} training samples "
                 "and {} testing samples"
                 "".format(len(training_labels), len(testing_labels)))

    # Compute some statistics about the training and testing sets
    if single_cmd is None:
        training_breakdown = {cmd_id: 0 for cmd_id in nwk_commands.values()}
        testing_breakdown = {cmd_id: 0 for cmd_id in nwk_commands.values()}
        for training_label in training_labels:
            training_breakdown[training_label] += 1
        for testing_label in testing_labels:
            testing_breakdown[testing_label] += 1
        fp = open(os.path.join(out_dirpath, "training-breakdown.tsv"), "w")
        for cmd_name in class_names:
            fp.write("{}\t{}\n".format(
                cmd_name, training_breakdown[nwk_commands[cmd_name]]))
        fp.close()
        fp = open(os.path.join(out_dirpath, "testing-breakdown.tsv"), "w")
        for cmd_name in class_names:
            fp.write("{}\t{}\n".format(
                cmd_name, testing_breakdown[nwk_commands[cmd_name]]))

    # Perform k-fold cross validation
    k = 5
    parameters = {
        "criterion": ["entropy", "gini"],
        "max_depth": [None, 8, 7, 6, 5, 4, 3, 2, 1],
    }
    logging.info("Tuning {} parameters using {}-fold cross validation..."
                 "".format(len(parameters.keys()), k))
    gscv = GridSearchCV(DecisionTreeClassifier(), parameters, cv=k)
    gscv.fit(training_table, training_labels)

    # Log the best score and parameters
    logging.info("Highest mean cross-validated score: {}"
                 "".format(gscv.best_score_))
    logging.info("Best set of parameters: {}".format(gscv.best_params_))

    # Write more detailed results in a file
    with open(os.path.join(out_dirpath, "cv-results.txt"), "w") as fp:
        fp.write("cv_results_ = {\n")
        for key in sorted(gscv.cv_results_.keys()):
            fp.write("    '{}': {},\n".format(key, gscv.cv_results_[key]))
        fp.write("}")

    # Use the best estimator as our classifier
    clf = gscv.best_estimator_

    # Plot the tree of the trained model
    dot_data = export_graphviz(clf,
                               out_file=None,
                               feature_names=dataset_features,
                               class_names=class_names,
                               rounded=True,
                               filled=True)
    graph = graphviz.Source(dot_data)
    graph.render(os.path.join(out_dirpath, "enc-nwk-cmd-tree"))

    # Export the tree in textual format as well
    with open(os.path.join(out_dirpath, "enc-nwk-cmd-tree.txt"), "w") as fp:
        fp.write(export_text(clf, feature_names=dataset_features))

    # Use the trained model to predict the class of the testing samples
    predictions = clf.predict(testing_table)

    # Write the results of classification metrics in a file
    fp = open(os.path.join(out_dirpath, "classification-report.txt"), "w")
    fp.write(metrics.classification_report(
        testing_labels, predictions, target_names=class_names, digits=3))
    fp.close()

    # Write the confusion matrix in a file
    confusion_matrix = metrics.confusion_matrix(testing_labels, predictions)
    np.savetxt(os.path.join(out_dirpath, "confusion-matrix.tsv"),
               confusion_matrix,
               fmt="%u",
               delimiter="\t",
               header="\t".join(class_names))

    # Log the accuracy score
    logging.info("Testing accuracy: {}".format(
        metrics.accuracy_score(testing_labels, predictions)))

    # Disconnect from the provided database
    config.db.disconnect()
