# The app's name for the scripts, read from project.yml (Core/Sources/AppCore/Brand.swift explains renaming).
# Source it from the repository root.
APP_NAME=$(sed -n 's/^ *APP_NAME: *//p' project.yml)
APP_ID=$(sed -n 's/^ *APP_ID: *//p' project.yml)
BUNDLE_ID=nl.dinkelworks.$APP_ID
# The website and the downloads (site/, site/downloads).
WEBSITE=https://www.$APP_ID.com
DOWNLOADS=https://download.$APP_ID.com
# The release version of the apps and the Linux program.
VERSION=$(sed -n 's/^ *MARKETING_VERSION: *"\{0,1\}\([^"]*\)"\{0,1\} *$/\1/p' project.yml)
