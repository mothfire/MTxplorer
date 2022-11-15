pragma solidity ^0.5.0;
contract IWillNeverDie {
    uint256 public a;
    uint256 public b;
    uint256 public c;

    function write_a(uint256 input) public {
        require(b == 3);
        require(c == 0xaffe);
        a = input;
    }

    function increase_b(uint256 input) public {
        b += 1;
    }

    function write_c(uint256 input) public {
        c = 0xaffe;
    }

    function boom() public {
        if (a == 0x1337) {
            selfdestruct(msg.sender);
        }
    }
}