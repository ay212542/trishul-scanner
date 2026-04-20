"""
TRISHUL Scanner — Setup Configuration
"""
from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="trishul-scanner",
    version="1.0.0",
    author="TRISHUL Project",
    description="Advanced modular open-source web vulnerability scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trishul-scanner/trishul",
    packages=find_packages(exclude=["tests*"]),
    package_data={
        "trishul": ["templates/*.j2"],
    },
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "rich>=13.7.0",
        "click>=8.1.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "trishul=trishul.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    keywords="security scanner vulnerability web pentest cybersecurity",
)
