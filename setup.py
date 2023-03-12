import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


setuptools.setup(
    name="drf-multiauth",
    version="0.0.1",
    author="Shubham Jaiswal",
    author_email="shubhamjaiswal6501@gmail.com",
    license="MIT",
    description="A simple authentication plugin for Django REST Framework to signup/login user via multiple email and phoneNumber",
    long_description=long_description,
    long_description_content_type = "text/markdown",
    url="https://github.com/shubham-techie/drf-multiauth",
    packages=setuptools.find_packages(exclude=['tests*', "LICENSE", "requirements.txt"]),       # ['django_multiauth']
    install_requires=[
        "pyjwt",
        "pyotp",
        "django",
        "djangorestframework",
        "djangorestframework-simplejwt",
    ],
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires = ">=3.6"
)