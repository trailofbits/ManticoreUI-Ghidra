format:
  just --justfile MUICore/justfile format
  gradle -p MUI spotlessApply

lint:
  just --justfile MUICore/justfile lint
  gradle -p MUI spotlessCheck

install:
  just --justfile MUICore/justfile install
  gradle -p MUI install
