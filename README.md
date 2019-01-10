# Venture Garden Group (Vibranium Valley) Single Sign On (SSO) Library

VGGSSO is a custom SSO (Single Sign On) library to be used by all (Strategic Business Units) SBUs, for authentication and authorization within the VGG eco-system connecting with the SSO Identity Server.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install vgg_sso.

```bash
pip install vgg_sso
```

## Usage

Setup the folowing configuration variables to enable access to the SSO Application Server

```python
# In the config.py file

VGG_SSO_CLIENT_ID = "python_sso_ro"
VGG_SSO_CLIENT_SECRET = "PythonSSORO"
VGG_SSO_CLIENT_USERNAME = "olukunle.ogunmokun@venturegardengroup.com"
VGG_SSO_CLIENT_PASSWORD = "P@ssw0rd"
```

Initialization of the library with respective python application

```python
from vgg_sso import VGGSSO

vgg_sso = VGGSSO(app)
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first or contact the developer to discuss what you would like to change.

Please make sure to update tests as appropriate.


## Dependencies
Python3
