{
  description = "vitrum development environment (TamaGo / USB armory Mk II)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go # >= 1.24: tamago-go bootstraps via `go tool`
              ubootTools # mkimage
              gcc-arm-embedded # arm-none-eabi-objcopy
              qemu # qemu-system-arm
              gnumake
            ];

            shellHook = ''
              # A host-exported GOROOT (e.g. pointing at another Go install)
              # breaks the devShell's toolchain; let go derive its own.
              unset GOROOT

              # Keep all build state self-contained in <repo>/.cache
              # (git-ignored): the tamago-go toolchain honors XDG_CACHE_HOME
              # (as does the Go build cache); GOPATH puts the module cache at
              # .cache/go/pkg/mod.
              # Do NOT export Go variables that the Makefile also defines as
              # make variables (GOFLAGS, GOMODCACHE, GOENV): make re-exports
              # its internal values of environment-origin variables to child
              # go processes, which choke on them.
              root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
              export XDG_CACHE_HOME="$root/.cache"
              export GOPATH="$root/.cache/go"
            '';
          };
        }
      );
    };
}
