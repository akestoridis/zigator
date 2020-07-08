# zigator

Zigator: Security analysis tool for Zigbee networks


## Disclaimer

Zigator is a software tool that analyzes the security of Zigbee networks, which is made available for benign research purposes only.
The users of this tool are responsible for making sure that they are compliant with their local laws and that they have proper permission from the affected network owners.


## Installation

You can install Zigator using pip for Python 3 as follows:
```
$ git clone https://github.com/akestoridis/zigator.git
$ cd zigator/
$ pip3 install .
```

The following command should display the version of Zigator that you installed:
```
$ zigator -v
```

If you get an error message that the `zigator` command was not found, make sure that your system's PATH environment variable includes the directory of the installed executable. For example, if it was installed in `~/.local/bin`, add the following line at the end of your `~/.bashrc` file:
```
export PATH=$PATH:~/.local/bin
```

After reloading your `~/.bashrc` file, you should be able to find the `zigator` command.


## License

Copyright (C) 2020 Dimitrios-Georgios Akestoridis

This project is licensed under the terms of the GNU General Public License version 2 only (GPL-2.0-only).
