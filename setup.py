from setuptools import setup
from setuptools.command.install import install
from setuptools.command.install_scripts import install_scripts
from distutils import log
import pathlib
import re
import os


here = pathlib.Path(__file__).parent.resolve()
content = (here / "README.md").read_text(encoding="utf-8")
summary = re.search("(?sia)What\?\n----\n(.+?)\n\n", content)[1]


setup(
    name="aionion",
    version="0.0.1",
    url="https://github.com/ultrafunkamsterdam/aionion",
    license="MIT",
    author="UltrafunkAmsterdam",
    author_email="",
    desc=summary,
    long_description=content,
    long_description_content_type="text/markdown",
    package_dir={"aionion": "aionion"},
    packages=["aionion"],
    include_package_data=True,
    install_requires=[
        "bs4",
        "lxml"
        "aiohttp>=3.8.0",
        "aiohttp_socks>=0.7.0",
        "stem>=1.8.0",
        "requests>=2.26",
        "async_timeout>=4.0.1",
    ],
)
