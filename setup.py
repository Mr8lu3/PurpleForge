"""Setup script for PurpleForge."""

from setuptools import setup, find_packages

setup(
    name="purpleforge",
    version="0.1.0",
    packages=find_packages(),
    package_data={
        "purpleforge.reporting": ["templates/*.j2"],
    },
    include_package_data=True,
)
