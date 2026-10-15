# Nix dev environment for angr.io: everything the demo generators and the
# screenshot helpers need that a bare machine may not have.
#
#   nix-shell                                   # with a nixpkgs channel configured
#   nix-shell -I nixpkgs=channel:nixpkgs-unstable
#
# Inside:  npm run gen:force        (demos: angr + angr-management via uv)
#          node scripts/shoot.mjs   (Playwright screenshots of the site)
#
# The Python side (angr, angr-management) is installed from PyPI by `uv run`;
# this shell only supplies the interpreter, the toolchains for the demo
# binaries, the native libraries the PySide6 (Qt) wheel dlopen()s at runtime,
# and a Chromium for Playwright (its own download needs host libraries that
# can't be mixed with nix's; the scripts pick up CHROME_PATH instead).
{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  packages = with pkgs; [
    python313
    uv
    nodejs
    go
    rustc
    gcc
    patchelf
    xdpyinfo
    dejavu_fonts
    chromium
  ];
  CHROME_PATH = "${pkgs.chromium}/bin/chromium";
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (
    with pkgs;
    [
      # Qt (PySide6 wheel) — angr-management for hero/shoot_gui.py
      libglvnd
      libxkbcommon
      fontconfig
      freetype
      glib
      dbus
      zlib
      zstd
      brotli
      krb5
      libdrm
      libx11
      libxcb
      libxcb-util
      libxcb-cursor
      libxcb-wm
      libxcb-image
      libxcb-keysyms
      libxcb-render-util
      stdenv.cc.cc.lib
    ]
  );
  FONTCONFIG_FILE = pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; };
}
