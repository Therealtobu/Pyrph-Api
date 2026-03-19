from setuptools import setup, find_packages

setup(
    name="pyrph",
    version="1.0.4",
    description="Python Obfuscation Engine — VM + Native + MBA",
    author="Therealtobu",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "pyrph.native": ["*.c", "*.h"],
    },
    install_requires=[
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "pyrph=pyrph.__main__:main",
        ],
    },
    python_requires=">=3.10",
)
