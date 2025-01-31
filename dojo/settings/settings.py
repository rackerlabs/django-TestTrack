
from split_settings.tools import include, optional

# See https://documentation.defectdojo.com/getting_started/configuration/ for options
# how to tune the configuration to your needs.

include(
    "settings_dist.py",
    optional("local_settings.py"),
)
