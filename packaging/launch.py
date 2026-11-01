"""Entry point of the standalone Vigie program that PyInstaller builds (see vigie.spec)."""

from vigie.standalone import main

raise SystemExit(main())
