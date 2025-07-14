#!/usr/bin/env python3
"""
Slack Permission System - Production-ready permission management for Slack bots
"""

from setuptools import setup, find_packages
import os

# Read long description from README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="slack-permission-system",
    version="1.0.0",
    author="Bruno Marcuche",
    author_email="bruno.marcuche@gmail.com",
    description="Production-ready permission management system for Slack bots",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bmarcuche/slack-permission-system",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Communications :: Chat",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "slack-permissions=slack_permissions.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="slack bot permissions security access-control devops automation",
    project_urls={
        "Bug Reports": "https://github.com/bmarcuche/slack-permission-system/issues",
        "Source": "https://github.com/bmarcuche/slack-permission-system",
        "Documentation": "https://slack-permission-system.readthedocs.io/",
    },
)
