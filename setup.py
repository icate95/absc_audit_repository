from setuptools import setup, find_packages

setup(
    name="absc_audit_system",
    version="0.1.0",
    description="Sistema di audit per le misure minime di sicurezza ABSC",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "paramiko",  # Per connessioni SSH
        "wmi",       # Per connessioni WMI
        "weasyprint", # Per generazione PDF
        "flask",     # Per interfaccia web
        "flask-login",     # Per interfaccia web
        "flask-wtf",     # Per interfaccia web
        "python-dotenv",
        "email_validator"
    ],
    entry_points={
        'console_scripts': [
            'absc-audit=absc_audit.ui.cli.commands:main',
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    python_requires='>=3.8',
)