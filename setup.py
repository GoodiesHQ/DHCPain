#!/usr/bin/env python3
from setuptools import setup, find_packages
from dhcpain import (
    __author__, __version__,
)

setup(  name="dhcpain",
        version=__version__,
        # packages=find_packages(),
        py_modules=["dhcpain"],
        install_requires=["scapy", "netifaces", "colorama"],
        description="DHCP Exhaustion utility",
        long_description=open("README.md", "r", encoding="utf-8").read(),
        author=__author__,
        author_email="aarcher73k@gmail.com",
        url="https://github.com/GoodiesHQ/DHCPain/",
        entry_points={
            "console_scripts": [
                "dhcpain = dhcpain:main",
            ],
        },
        classifiers = [
            "License :: OSI Approved :: GNU Affero General Public License v3",
            "Topic :: Security",
            "Topic :: System :: Networking",
        ],
)
