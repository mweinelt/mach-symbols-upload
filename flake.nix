{
  inputs = {
    git-hooks.url = "github:cachix/git-hooks.nix";
    git-hooks.inputs.nixpkgs.follows = "nixpkgs";

    nixpkgs.url = "github:nixos/nixpkgs?ref=nixpkgs-unstable";

    pyproject-build-systems.url = "github:pyproject-nix/build-system-pkgs";
    pyproject-build-systems.inputs.pyproject-nix.follows = "pyproject-nix";
    pyproject-build-systems.inputs.uv2nix.follows = "uv2nix";
    pyproject-build-systems.inputs.nixpkgs.follows = "nixpkgs";

    pyproject-nix.url = "github:pyproject-nix/pyproject.nix";
    pyproject-nix.inputs.nixpkgs.follows = "nixpkgs";

    uv2nix.url = "github:pyproject-nix/uv2nix";
    uv2nix.inputs.pyproject-nix.follows = "pyproject-nix";
    uv2nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      git-hooks,
      nixpkgs,
      pyproject-build-systems,
      pyproject-nix,
      self,
      uv2nix,
      ...
    }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      lib = pkgs.lib;

      python = pkgs.python313;

      workspace = uv2nix.lib.workspace.loadWorkspace {
        # pass filtered repository root, so we don't invalidate the source unnecessarily
        workspaceRoot = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./pyproject.toml
            ./src
            ./uv.lock
          ];
        };
      };

      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };

      pyprojectOverrides = final: prev: {
        python-ldap = prev.python-ldap.overrideAttrs (old: {
          nativeBuildInputs =
            old.nativeBuildInputs or [ ]
            ++ (with final; [
              setuptools
              standard-distutils
            ]);
          buildInputs = with pkgs; [
            cyrus_sasl
            openldap
          ];
        });
      };

      # Construct package set
      pythonSet =
        # Use base package set from pyproject.nix builders
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        }).overrideScope
          (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.default
              overlay
              pyprojectOverrides
            ]
          );

      virtualenv = pythonSet.mkVirtualEnv "mach-symbols-upload-venv" workspace.deps.all;
    in
    {
      checks.x86_64-linux.pre-commit = git-hooks.lib.x86_64-linux.run {
        src = ./.;
        hooks = {
          ruff.enable = true;
          ruff-format.enable = true;
          ty = {
            enable = true;
            entry = toString [
              (lib.getExe pkgs.ty)
              "check"
              "--extra-search-path"
              "${virtualenv}/${python.sitePackages}"
            ];
            package = pkgs.ty;
            files = "\\.py$";
          };
        };
      };

      devShells.x86_64-linux.default = pkgs.mkShellNoCC {
        packages =
          with pkgs;
          [
            uv
            virtualenv
          ]
          ++ self.checks.x86_64-linux.pre-commit.enabledPackages;

        inherit (self.checks.x86_64-linux.pre-commit) shellHook;
      };
    };
}
