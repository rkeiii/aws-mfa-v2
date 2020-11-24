from setuptools import setup

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='aws-mfa-v2',
    version='0.2.0',
    description='Manage AWS MFA Security Credentials',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='GPLv3+',
    author='Ron Ellis',
    author_email='rkeiii@protonmail.com',
    packages=['awsmfav2'],
    entry_points={
        'console_scripts': [
            'aws-mfa=awsmfav2.aws_mfa:entrypoint',
        ],
    },
    url='https://github.com/rkeiii/aws-mfa-v2',
    python_requires='>=3.6',
    install_requires=['boto3', 'configparser', 'argparse'],
    extras_require={
        'yubikey': ['yubikey-manager']
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
    ],
)
