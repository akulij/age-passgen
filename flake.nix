{
    inputs = {
        flake-utils.url = "github:numtide/flake-utils";
    };
    outputs = {self, nixpkgs, flake-utils, ...}@inputs:
        flake-utils.lib.eachDefaultSystem
            (system:
                let pkgs = nixpkgs.legacyPackages.${system}; in
                {
                    devShells.default = import ./shell.nix { inherit pkgs; };

                    packages.default = pkgs.buildGoModule {
                        pname = "age-passgen";
                        version = "unversioned";

                        src = ./.;

                        vendorHash = "sha256-Y6R8c9PzRq0tJ0b06f0LuFfrdFvxQ7h/86a6gg6UOro=";
                    };

                    apps.default = {
                        type = "app";
                        program = "${self.packages.${system}.default}/bin/age-passgen";
                    };
                }
            );
}
