export interface EcosystemProject {
  name: string;
  tagline: string;
  href: string;
}

/** angr is a platform: each subproject is useful on its own. */
export const ecosystem: EcosystemProject[] = [
  {
    name: "angr",
    tagline: "The binary analysis platform itself.",
    href: "https://github.com/angr/angr",
  },
  {
    name: "angr-management",
    tagline: "The graphical interface for angr.",
    href: "https://github.com/angr/angr-management",
  },
  {
    name: "srcdump",
    tagline: "Like objdump, but dumps decompiled source code.",
    href: "https://github.com/angr/srcdump",
  },
  {
    name: "CLE",
    tagline: "Loads binaries and their libraries into memory.",
    href: "https://github.com/angr/cle",
  },
  {
    name: "PyVEX",
    tagline: "Python bindings to the VEX intermediate language.",
    href: "https://github.com/angr/pyvex",
  },
  {
    name: "pypcode",
    tagline: "Python bindings to Ghidra's P-code lifter.",
    href: "https://github.com/angr/pypcode",
  },
  {
    name: "archinfo",
    tagline: "A library of CPU architecture descriptions.",
    href: "https://github.com/angr/archinfo",
  },
  {
    name: "angrop",
    tagline: "Automatic ROP chain generation.",
    href: "https://github.com/angr/angrop",
  },
];
