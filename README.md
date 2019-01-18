# Venture Garden Group (Vibranium Valley) Single Sign On (SSO) Library

VGGSSO is a custom SSO (Single Sign On) library to be used by all (Strategic Business Units) SBUs, for authentication and authorization within the VGG eco-system connecting with the SSO Identity Server.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install vgg_sso.

```bash
pip install vgg-sso
```

## Usage

Setup the folowing configuration variables to enable access to the SSO Application Server

```python
# In the config.py / settings.py file

VGG_SSO_CLIENT_ID="clientId",
VGG_SSO_CLIENT_SECRET="clientSecret",
VGG_SSO_CLIENT_RO_ID="clientResourceOwnerId",
VGG_SSO_CLIENT_RO_SECRET="clientResourceOwnerSecret"

```

Initialization of the library with respective python application

```python
from vgg_sso import VGGSSO

# Set debug as True for staging environment and False for production environment
# Set config_data to be a dictionary with keys representing the configuration variables 

config_data = dict(
    VGG_SSO_CLIENT_ID="clientId",
    VGG_SSO_CLIENT_SECRET="clientSecret",
    VGG_SSO_CLIENT_RO_ID="clientResourceOwnerId",
    VGG_SSO_CLIENT_RO_SECRET="clientResourceOwnerSecret"
)

vgg_sso = VGGSSO(debug=True, config_data=config_data)
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first or contact the developer to discuss what you would like to change.

Please make sure to update tests as appropriate.


## Dependencies
Python3

urllib
