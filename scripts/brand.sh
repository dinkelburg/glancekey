# The app's name for the scripts, read from project.yml (Core/Sources/AppCore/Brand.swift explains renaming).
# Source it from the repository root.
APP_NAME=$(sed -n 's/^ *APP_NAME: *//p' project.yml)
APP_ID=$(sed -n 's/^ *APP_ID: *//p' project.yml)
BUNDLE_ID=nl.dinkelworks.$APP_ID
