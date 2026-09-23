{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    (python3.withPackages (ps: with ps; [
      pip
      flask
    ]))
    tcpdump
    wireshark-cli  # provides tshark
    docker-compose
  ];

  shellHook = ''
    # Create venv for ja4plus (not in nixpkgs)
    if [ ! -d .venv ]; then
      python3 -m venv .venv --system-site-packages
      .venv/bin/pip install -q ja4plus
    fi
    source .venv/bin/activate
    echo "Fingerprinting harness shell ready"
    echo "  tshark: $(which tshark)"
    echo "  tcpdump: $(which tcpdump)"
    echo "  docker: $(which docker)"
  '';
}
