# tunnelbana task runner — run `just` to list recipes.

# Version is read from the workspace Cargo.toml ([workspace.package] version);
# the tunnelbana binary crate inherits it via `version.workspace = true`.
version := `grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"(.*)".*/\1/'`
registry := "docker.sunet.se"
image := registry / "tunnelbana:" + version

# List available recipes.
default:
    @just --list

# Print the version / image tag derived from Cargo.toml.
print-version:
    @echo {{image}}

# Build the production container, tagged docker.sunet.se/tunnelbana:VERSION.
build:
    docker build -t {{image}} .

# Push the tagged image to the registry (run `build` first).
push:
    docker push {{image}}

# Build then push.
release: build push
