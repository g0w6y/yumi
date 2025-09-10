from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="yumi-scanner",
    version="2.0.0",
    author="Davy Cipher",
    author_email="davycypher@gmail.com",
    description="Yumi v2 - An intelligent, asynchronous JS Recon Engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cypherdavy/yumi",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "yumi = yumi.main:start"
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Bug Tracking",
    ],
    python_requires='>=3.8',
)
