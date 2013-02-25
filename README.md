iptables gem
------------

This gem provides a library that is a higher-level abstration for iptables. It can be used for parsing `iptables-save` output and producing `iptables-restore` compatible output.

Tools
=====

### iptables-decode

This tool takes in the output of iptables-save and returns a hash in JSON. This is useful for debugging the parser. You can either run iptabes-save directly:

    iptables-save | iptables-decode

Or pipe from the persisted file:

    cat /etc/iptables/rules.v4 | iptables-decode
