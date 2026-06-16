from setuptools import setup, find_packages

setup(
    name="shadowrecon",
    version="1.0.0",
    description="ShadowRecon — Web Application Security Scanner",
    author="ShadowRecon Team",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        # Core
        "pydantic>=2.5.0",
        "httpx>=0.26.0",
        "httpx[socks]>=0.26.0",
        "sqlalchemy>=2.0.0",
        "aiosqlite>=0.19.0",
        "pyyaml>=6.0",
        "python-Levenshtein>=0.23.0",
        "networkx>=3.0",
        # Web backend
        "fastapi>=0.109.0",
        "uvicorn[standard]>=0.25.0",
        "websockets>=12.0",
        "python-multipart>=0.0.6",
        # Reporting
        "jinja2>=3.1.0",
        # LLM
        "httpx>=0.26.0",
    ],
    extras_require={
        "pdf": ["weasyprint>=60.0"],
        "dev": ["pytest", "pytest-asyncio", "black", "ruff"],
    },
    entry_points={
        "console_scripts": [
            "shadowrecon=main:main",
        ],
    },
    python_requires=">=3.10",
)
