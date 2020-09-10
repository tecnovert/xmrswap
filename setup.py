import setuptools
import re
import io

__version__ = re.search(
    r'__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
    io.open('xmrswap/__init__.py', encoding='utf_8_sig').read()
).group(1)

setuptools.setup(
    name="xmrswaptool",
    version=__version__,
    author="tecnovert",
    author_email="tecnovert@tecnovert.net",
    description="h4sh3d Bitcoin–Monero Cross-chain Atomic Swap protocol implementation",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="",
    packages=setuptools.find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Linux",
    ],
    install_requires=[
    ],
    entry_points={
        "console_scripts": [
            "xmrswaptool=bin.xmrswaptool:main",
        ]
    },
    test_suite="tests.xmrswap.test_suite"
)
