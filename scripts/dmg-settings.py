# dmgbuild settings for the Mac download (scripts/release.sh): the app next to a link to Applications, so you
# drag it across. Usage: dmgbuild -s scripts/dmg-settings.py -D app=<path to the .app> <volume name> <file.dmg>
import os.path

app = defines["app"]
name = os.path.basename(app)

format = "ULFO"
filesystem = "APFS"
files = [app]
symlinks = {"Applications": "/Applications"}
icon = os.path.join(app, "Contents/Resources/AppIcon.icns")  # the disk's icon in Finder

window_rect = ((200, 200), (560, 340))
default_view = "icon-view"
show_toolbar = False
show_status_bar = False
show_pathbar = False
show_sidebar = False
icon_size = 128
text_size = 13
icon_locations = {name: (150, 140), "Applications": (410, 140)}
