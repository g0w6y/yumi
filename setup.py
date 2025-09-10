setup(
    name="yumi-scanner",
    version="2.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "rich",
        "pyfiglet",
        "httpx[http2]",
        "beautifulsoup4",
        "jsbeautifier",
        "esprima",
        "pyyaml",
    ],
    entry_points={
        "console_scripts": [
            "yumi = yumi.main:start"
        ],
    },
    author="Davy Cipher",
    description="Yumi v2 - An intelligent, asynchronous JS Recon Engine",
    url="https://github.com/cypherdavy/yumi"
)
