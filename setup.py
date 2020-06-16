#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(  name="dhcpain",
        packages=find_packages(),
        install_requires=["scapy", "netifaces", "colorama"],
        description="DHCP Exhaustion utility",
        long_description=open("README.md", "r", encoding="utf-8").read(),
        author="Austin Archer",
        author_email="aarcher73k@gmail.com",
        url="https://github.com/GoodiesHQ/DHCPain/",
        entry_points={
            "console_scripts": [
                "dhcpain = dhcpain:main",
            ],
        },
        classifiers = [
            "License :: OSI Approved :: GPL3 License",
            "Topic :: Security :: Networking",
        ],
)
