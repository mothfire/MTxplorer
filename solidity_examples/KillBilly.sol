pragma solidity ^0.5.7;

contract KillBilly {
    address private owner;
    bool private is_killable;
    mapping (address => bool) public approved_killers;

    constructor() public {
        owner = msg.sender;
        is_killable = false;
    }

    function killerize(address addr) public {
        approved_killers[addr] = true;
    }

    function activatekillability() public {
        require(approved_killers[msg.sender] == true);
        is_killable = true;
    }

    function commencekilling() public {
        require(is_killable == true);
        selfdestruct(msg.sender);
    }

    function() external payable {}
}
