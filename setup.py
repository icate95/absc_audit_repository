from setuptools import setup, find_packages
import sys

# Read requirements
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith('#') and not line.startswith('# ')
    ]

# Conditional Windows dependencies
if sys.platform == 'win32':
    requirements.extend([
        'pywin32>=306',
        'wmi>=1.5.1'
    ])

setup(
    name='absc-audit-system',
    version='0.2.0',
    author='ABSC Audit Team',
    description='Automated Security Audit System for ABSC Compliance',

    packages=find_packages(exclude=['tests*', 'docs']),

    install_requires=requirements,

    entry_points={
        'console_scripts': [
            'absc-audit=absc_audit.ui.cli.commands:main',
        ],
    },

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
    ],

    python_requires='>=3.8,<3.14',

    extras_require={
        'dev': [
            'pytest',
            'pytest-cov',
            'bandit',
            'black',
            'mypy',
        ],
        'windows': [
            'pywin32>=306',
            'wmi>=1.5.1',
        ],
        'docs': [
            'sphinx',
            'sphinx-rtd-theme',
        ],
    },

    keywords='security audit compliance absc infosec',
)