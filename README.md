# This is an experimental proof-of-concept tool, and this project is no longer maintained.

# MTxplorer

A security analysis tool for EVM bytecode based on [Mythril](https://github.com/ConsenSys/mythril).

Our paper: Multi-transaction Sequence Vulnerability Detection for Smart Contracts Based on Inter-path Data Dependency ([QRS 2022](https://qrs22.techconf.org/))


## Usage


```bash
git clone https://github.com/mothfire/MTxplorer.git
cd MTxplorer
pip3 install -r requirements.txt
```

Install Solidity Compiler (solc).

Run:

```
$ python3 myth analyze <solidity-file> -t <number(>=2)>
```

Specify the maximum number of transaction to explore with `-t <number>`.

The command line options are the same as Mythril, please refer to [Mythril](https://github.com/ConsenSys/mythril).


