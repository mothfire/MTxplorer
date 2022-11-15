# This is an experimental proof-of-concept tool, and this project is no longer maintained.

# MTxplorer

A security analysis tool for EVM bytecode based on [Mythril](https://github.com/ConsenSys/mythril).


## Usage


```bash
git clone https://github.com/mothfire/MTxplorer.git
cd MTxplorer
pip3 install -r requirements.txt
```

Run:

```
$ python3 myth analyze <solidity-file> -t <number(>=2)>
```

Specify the maximum number of transaction to explore with `-t <number>`.

The command line options are the same as Mythril, please refer to [Mythril](https://github.com/ConsenSys/mythril).


